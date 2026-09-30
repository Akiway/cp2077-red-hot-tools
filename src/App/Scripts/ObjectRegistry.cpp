#include "ObjectRegistry.hpp"
#include "Core/Facades/Log.hpp"
#include "Red/ISerializable.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>

namespace
{
constexpr auto MaxNumObjects = 0x350000;
constexpr auto CreatorSampleInterval = 1024ull;
constexpr auto CreatorSampleCapacity = 8192ull;
constexpr auto ExactSampleWindow = 4096ull;
constexpr auto StallWarningDelay = 2'000ull;
constexpr auto StallWarningInterval = 5'000ull;
constexpr auto LockWaitWarningDelay = 1'000ull;

Red::ClassLocator<Red::IScriptable> s_IScriptableType;

enum class ShrinkPhase : uint8_t
{
    Idle,
    Scanning,
    Releasing,
};

struct CreationSample
{
    uint64_t sequence;
    uint64_t timestamp;
    uint64_t registrySize;
    uintptr_t object;
    uintptr_t caller;
    Red::CBaseRTTIType* type;
    uint32_t threadID;
    uint32_t weight;
};

struct SampleAggregate
{
    uintptr_t key;
    uint64_t estimatedCount;
    uint64_t sampleCount;
    uint64_t lastSequence;
    uint32_t lastThreadID;
};

struct AddressInfo
{
    std::string module;
    uintptr_t offset;
};

struct ModuleRange
{
    uintptr_t begin;
    uintptr_t end;
};

std::atomic<ShrinkPhase> s_shrinkPhase{ShrinkPhase::Idle};
std::atomic<uint64_t> s_shrinkGeneration{};
std::atomic<uint64_t> s_shrinkStartedAt{};
std::atomic<uint64_t> s_shrinkTotal{};
std::atomic<uint64_t> s_shrinkProcessed{};
std::atomic<uint64_t> s_shrinkExpired{};
std::atomic<uint64_t> s_shrinkSurvivors{};
std::atomic<uint64_t> s_shrinkReleaseTotal{};
std::atomic<uint64_t> s_shrinkReleased{};
std::atomic<uint64_t> s_shrinkCurrentIndex{};
std::atomic<uintptr_t> s_shrinkCurrentObject{};
std::atomic<uintptr_t> s_shrinkCurrentRefCount{};
std::atomic<uint32_t> s_shrinkOwnerThreadID{};

std::atomic<uint64_t> s_createdObjects{};
std::atomic<uint64_t> s_registrySize{};
std::atomic<uint32_t> s_registryWaiters{};
std::atomic<uint32_t> s_lastWaiterThreadID{};
std::atomic<uintptr_t> s_lastWaiterObject{};
std::atomic<uintptr_t> s_lastWaiterCaller{};

std::array<CreationSample, CreatorSampleCapacity> s_creationSamples{};
uint64_t s_nextCreationSample{};
std::mutex s_creationSamplesLock;
std::jthread s_shrinkMonitor;

uint64_t GetTimestamp()
{
    return GetTickCount64();
}

ModuleRange GetCurrentModuleRange()
{
    static const auto range = [] {
        HMODULE result{};
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCWSTR>(&GetCurrentModuleRange), &result);

        const auto begin = reinterpret_cast<uintptr_t>(result);
        if (!begin)
        {
            return ModuleRange{};
        }

        const auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(begin);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return ModuleRange{};
        }

        const auto ntHeader = reinterpret_cast<const IMAGE_NT_HEADERS*>(begin + dosHeader->e_lfanew);
        if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
        {
            return ModuleRange{};
        }

        return ModuleRange{begin, begin + ntHeader->OptionalHeader.SizeOfImage};
    }();

    return range;
}

uintptr_t GetExternalCaller()
{
    // The generic hook handler and this callback both live in RHT. Skip their frames so creator attribution points
    // at the game or plugin that actually requested the handle.
    std::array<void*, 16> frames{};
    const auto frameCount = CaptureStackBackTrace(0, static_cast<DWORD>(frames.size()), frames.data(), nullptr);
    const auto currentModule = GetCurrentModuleRange();
    if (!currentModule.begin)
    {
        return 0;
    }

    for (size_t i = 0; i < frameCount; ++i)
    {
        const auto frame = reinterpret_cast<uintptr_t>(frames[i]);
        if (frame < currentModule.begin || frame >= currentModule.end)
        {
            return frame;
        }
    }

    return 0;
}

const char* GetPhaseName(ShrinkPhase aPhase)
{
    switch (aPhase)
    {
    case ShrinkPhase::Scanning:
        return "scanning";
    case ShrinkPhase::Releasing:
        return "releasing";
    default:
        return "idle";
    }
}

AddressInfo GetAddressInfo(uintptr_t aAddress)
{
    HMODULE module{};
    if (aAddress &&
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCWSTR>(aAddress), &module))
    {
        std::array<wchar_t, 1024> path{};
        const auto length = GetModuleFileNameW(module, path.data(), static_cast<DWORD>(path.size()));
        std::string name{"<unknown>"};
        if (length)
        {
            try
            {
                name = std::filesystem::path(std::wstring_view(path.data(), length)).filename().string();
            }
            catch (...)
            {
            }
        }

        return {name, aAddress - reinterpret_cast<uintptr_t>(module)};
    }

    return {"<unknown>", aAddress};
}

void RecordCreationSample(uint64_t aSequence, uint64_t aRegistrySize, Red::ISerializable* aObject, uintptr_t aCaller,
                          uint32_t aWeight)
{
    const auto type = aObject ? aObject->GetType() : nullptr;
    const CreationSample sample{
        aSequence, GetTimestamp(), aRegistrySize,        reinterpret_cast<uintptr_t>(aObject),
        aCaller,   type,           GetCurrentThreadId(), aWeight,
    };

    std::lock_guard lock(s_creationSamplesLock);
    s_creationSamples[s_nextCreationSample++ % s_creationSamples.size()] = sample;
}

std::vector<CreationSample> CopyCreationSamples()
{
    std::vector<CreationSample> samples;
    samples.reserve(s_creationSamples.size());

    std::lock_guard lock(s_creationSamplesLock);
    for (const auto& sample : s_creationSamples)
    {
        if (sample.sequence)
        {
            samples.emplace_back(sample);
        }
    }

    std::ranges::sort(samples, {}, &CreationSample::sequence);
    return samples;
}

template<typename TKeySelector>
std::vector<SampleAggregate> AggregateSamples(const std::vector<CreationSample>& aSamples, TKeySelector aKeySelector)
{
    std::map<uintptr_t, SampleAggregate> aggregateMap;

    for (const auto& sample : aSamples)
    {
        const auto key = aKeySelector(sample);
        auto it = aggregateMap.try_emplace(key, SampleAggregate{key, 0, 0, 0, 0}).first;
        auto& aggregate = it->second;
        aggregate.estimatedCount += sample.weight;
        ++aggregate.sampleCount;

        if (sample.sequence >= aggregate.lastSequence)
        {
            aggregate.lastSequence = sample.sequence;
            aggregate.lastThreadID = sample.threadID;
        }
    }

    std::vector<SampleAggregate> aggregates;
    aggregates.reserve(aggregateMap.size());
    for (const auto& [key, aggregate] : aggregateMap)
    {
        aggregates.emplace_back(aggregate);
    }

    std::ranges::sort(
        aggregates, [](const auto& aLeft, const auto& aRight) { return aLeft.estimatedCount > aRight.estimatedCount; });

    return aggregates;
}

void LogCreationSamples(uint64_t aGeneration)
{
    const auto samples = CopyCreationSamples();
    if (samples.empty())
    {
        Core::Log::Warning("[ObjectRegistry] Shrink #{} has no creator samples.", aGeneration);
        return;
    }

    uint64_t representedObjects{};
    for (const auto& sample : samples)
    {
        representedObjects += sample.weight;
    }

    const auto& first = samples.front();
    const auto& last = samples.back();
    const auto sampleDuration = last.timestamp - first.timestamp;
    const auto creationRate = sampleDuration ? static_cast<double>(last.sequence - first.sequence) * 1000.0 /
                                                   static_cast<double>(sampleDuration)
                                             : 0.0;

    Core::Log::Warning("[ObjectRegistry] Shrink #{} creator history: samples={} representedObjects={} sequence={}-{} "
                       "registrySize={}-{} duration={}ms rate={:.1f}/s.",
                       aGeneration, samples.size(), representedObjects, first.sequence, last.sequence,
                       first.registrySize, last.registrySize, sampleDuration, creationRate);

    auto typeAggregates = AggregateSamples(
        samples, [](const CreationSample& aSample) { return reinterpret_cast<uintptr_t>(aSample.type); });

    const auto typeCount = std::min<size_t>(typeAggregates.size(), 8);
    for (size_t i = 0; i < typeCount; ++i)
    {
        const auto& aggregate = typeAggregates[i];
        const auto type = reinterpret_cast<Red::CBaseRTTIType*>(aggregate.key);
        const auto resolvedTypeName = type ? type->GetName().ToString() : nullptr;
        const auto typeName = resolvedTypeName ? resolvedTypeName : "<unknown>";
        Core::Log::Warning(
            "[ObjectRegistry] Shrink #{} top type {}: estimated={} samples={} type={} typeAddress=0x{:X} "
            "lastThread={} lastSequence={}.",
            aGeneration, i + 1, aggregate.estimatedCount, aggregate.sampleCount, typeName, aggregate.key,
            aggregate.lastThreadID, aggregate.lastSequence);
    }

    auto callerAggregates = AggregateSamples(samples, [](const CreationSample& aSample) { return aSample.caller; });
    const auto callerCount = std::min<size_t>(callerAggregates.size(), 8);
    for (size_t i = 0; i < callerCount; ++i)
    {
        const auto& aggregate = callerAggregates[i];
        const auto address = GetAddressInfo(aggregate.key);
        Core::Log::Warning("[ObjectRegistry] Shrink #{} top caller {}: estimated={} samples={} address=0x{:X} "
                           "location={}+0x{:X} lastThread={} lastSequence={}.",
                           aGeneration, i + 1, aggregate.estimatedCount, aggregate.sampleCount, aggregate.key,
                           address.module, address.offset, aggregate.lastThreadID, aggregate.lastSequence);
    }

    const auto recentCount = std::min<size_t>(samples.size(), 8);
    for (size_t i = samples.size() - recentCount; i < samples.size(); ++i)
    {
        const auto& sample = samples[i];
        const auto resolvedTypeName = sample.type ? sample.type->GetName().ToString() : nullptr;
        const auto typeName = resolvedTypeName ? resolvedTypeName : "<unknown>";
        const auto address = GetAddressInfo(sample.caller);
        Core::Log::Warning(
            "[ObjectRegistry] Shrink #{} recent creator: sequence={} registrySize={} object=0x{:X} type={} "
            "thread={} caller=0x{:X} ({}+0x{:X}) weight={}.",
            aGeneration, sample.sequence, sample.registrySize, sample.object, typeName, sample.threadID, sample.caller,
            address.module, address.offset, sample.weight);
    }
}

void MonitorShrinks(std::stop_token aStopToken)
{
    // This thread deliberately observes atomics only. Taking s_registryLock here would hide the exact lock convoy
    // that these diagnostics are intended to report.
    uint64_t observedGeneration{};
    uint64_t lastProgress{};
    uint64_t lastProgressAt{};
    uint64_t lastWarningAt{};
    ShrinkPhase observedPhase{ShrinkPhase::Idle};
    bool creationSamplesLogged{};

    while (!aStopToken.stop_requested())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));

        const auto phase = s_shrinkPhase.load(std::memory_order_acquire);
        if (phase == ShrinkPhase::Idle)
        {
            observedGeneration = 0;
            observedPhase = ShrinkPhase::Idle;
            creationSamplesLogged = false;
            continue;
        }

        const auto now = GetTimestamp();
        const auto generation = s_shrinkGeneration.load(std::memory_order_relaxed);
        const auto processed = s_shrinkProcessed.load(std::memory_order_relaxed);
        const auto released = s_shrinkReleased.load(std::memory_order_relaxed);
        const auto progress = phase == ShrinkPhase::Scanning ? processed : released;

        const auto generationChanged = generation != observedGeneration;
        if (generationChanged || phase != observedPhase)
        {
            if (generationChanged)
            {
                creationSamplesLogged = false;
            }

            observedGeneration = generation;
            observedPhase = phase;
            lastProgress = progress;
            lastProgressAt = now;
            lastWarningAt = 0;
        }
        else if (progress != lastProgress)
        {
            lastProgress = progress;
            lastProgressAt = now;
        }

        const auto startedAt = s_shrinkStartedAt.load(std::memory_order_relaxed);
        const auto elapsed = now - startedAt;
        if (elapsed < StallWarningDelay || (lastWarningAt && now - lastWarningAt < StallWarningInterval))
        {
            continue;
        }

        const auto currentObject = s_shrinkCurrentObject.load(std::memory_order_relaxed);
        const auto waiterCaller = s_lastWaiterCaller.load(std::memory_order_relaxed);
        const auto waiterAddress = GetAddressInfo(waiterCaller);

        Core::Log::Warning(
            "[ObjectRegistry] Shrink #{} still active after {}ms: phase={} ownerThread={} scan={}/{} "
            "currentIndex={} currentObject=0x{:X} currentRefCount=0x{:X} expired={} survivors={} "
            "release={}/{} noProgress={}ms "
            "waiters={} lastWaiterThread={} lastWaiterObject=0x{:X} lastWaiterCaller=0x{:X} ({}+0x{:X}).",
            generation, elapsed, GetPhaseName(phase), s_shrinkOwnerThreadID.load(std::memory_order_relaxed), processed,
            s_shrinkTotal.load(std::memory_order_relaxed), s_shrinkCurrentIndex.load(std::memory_order_relaxed),
            currentObject, s_shrinkCurrentRefCount.load(std::memory_order_relaxed),
            s_shrinkExpired.load(std::memory_order_relaxed), s_shrinkSurvivors.load(std::memory_order_relaxed),
            released, s_shrinkReleaseTotal.load(std::memory_order_relaxed), now - lastProgressAt,
            s_registryWaiters.load(std::memory_order_relaxed), s_lastWaiterThreadID.load(std::memory_order_relaxed),
            s_lastWaiterObject.load(std::memory_order_relaxed), waiterCaller, waiterAddress.module,
            waiterAddress.offset);

        if (!creationSamplesLogged)
        {
            LogCreationSamples(generation);
            creationSamplesLogged = true;
        }

        lastWarningAt = now;
    }
}
} // namespace

void App::ObjectRegistry::OnBootstrap()
{
    s_objects.reserve(MaxNumObjects);

    s_shrinkMonitor = std::jthread(MonitorShrinks);

    Hook<Raw::ISerializable::CreateHandle>(&OnCreateHandle);
}

void App::ObjectRegistry::OnShutdown()
{
    if (s_shrinkMonitor.joinable())
    {
        s_shrinkMonitor.request_stop();
        s_shrinkMonitor.join();
    }
}

void* App::ObjectRegistry::OnCreateHandle(Red::Handle<Red::ISerializable>& aHandle, Red::ISerializable* aObject)
{
    auto isNewHandle = aObject && !aObject->ref.refCount;

    Raw::ISerializable::CreateHandle(aHandle, aObject);

    if (isNewHandle)
    {
        const auto sequence = s_createdObjects.fetch_add(1, std::memory_order_relaxed) + 1;
        const auto threadID = GetCurrentThreadId();
        const auto waitStartedAt = GetTimestamp();
        const auto approximateRegistrySize = s_registrySize.load(std::memory_order_relaxed);
        const auto shouldCaptureCaller = sequence % CreatorSampleInterval == 0 ||
                                         approximateRegistrySize + ExactSampleWindow >= MaxNumObjects ||
                                         s_shrinkPhase.load(std::memory_order_acquire) != ShrinkPhase::Idle;
        auto caller = shouldCaptureCaller ? GetExternalCaller() : 0;

        s_lastWaiterThreadID.store(threadID, std::memory_order_relaxed);
        s_lastWaiterObject.store(reinterpret_cast<uintptr_t>(aObject), std::memory_order_relaxed);
        s_lastWaiterCaller.store(caller, std::memory_order_relaxed);
        s_registryWaiters.fetch_add(1, std::memory_order_release);

        uint64_t waitDuration{};
        {
            std::unique_lock lock(s_registryLock);
            waitDuration = GetTimestamp() - waitStartedAt;
            s_registryWaiters.fetch_sub(1, std::memory_order_release);

            s_objects.emplace_back(aHandle);

            const auto registrySize = s_objects.size();
            s_registrySize.store(registrySize, std::memory_order_relaxed);
            const auto exactSample = registrySize + ExactSampleWindow >= MaxNumObjects;
            if (exactSample || sequence % CreatorSampleInterval == 0)
            {
                if (!caller)
                {
                    caller = GetExternalCaller();
                }

                RecordCreationSample(sequence, registrySize, aObject, caller,
                                     exactSample ? 1u : static_cast<uint32_t>(CreatorSampleInterval));
            }

            if (registrySize >= MaxNumObjects - 1)
            {
                Shrink("capacity threshold");
            }
        }

        if (waitDuration >= LockWaitWarningDelay)
        {
            if (!caller)
            {
                caller = GetExternalCaller();
            }

            const auto address = GetAddressInfo(caller);
            LogWarning("[ObjectRegistry] CreateHandle waited {}ms for the registry lock: thread={} object=0x{:X} "
                       "caller=0x{:X} ({}+0x{:X}).",
                       waitDuration, threadID, reinterpret_cast<uintptr_t>(aObject), caller, address.module,
                       address.offset);
        }
    }

    return &aHandle;
}

void App::ObjectRegistry::CollectSerializables(Red::DynArray<Red::WeakHandle<Red::ISerializable>>& aOut)
{
    std::shared_lock lock(s_registryLock);

    for (const auto& weak : s_objects)
    {
        if (!weak.Expired())
        {
            aOut.EmplaceBack(weak);
        }
    }
}

void App::ObjectRegistry::CollectScriptables(Red::DynArray<Red::WeakHandle<Red::IScriptable>>& aOut)
{
    std::shared_lock lock(s_registryLock);

    for (const auto& weak : s_objects)
    {
        if (!weak.Expired() && weak.instance->GetType()->IsA(s_IScriptableType))
        {
            aOut.EmplaceBack(*reinterpret_cast<const Red::WeakHandle<Red::IScriptable>*>(&weak));
        }
    }
}

void App::ObjectRegistry::CreateSnapshot()
{
    std::shared_lock lock1(s_registryLock);
    std::unique_lock lock2(s_snapshotLock);

    s_snapshot.clear();

    for (const auto& weak : s_objects)
    {
        if (weak.Expired())
            continue;

        if (!weak.instance->GetType()->IsA(s_IScriptableType))
            continue;

        auto cls = weak.instance->GetType();

        if (!cls->holderSize)
            continue;

        auto it = s_snapshot.find(cls->GetName());

        if (it != s_snapshot.end())
            continue;

        auto& desc = s_snapshot.insert({cls->name, {}}).first.value();

        Red::DynArray<Red::CProperty*> props;
        cls->GetProperties(props);

        for (const auto& prop : props)
        {
            if (prop->flags.inValueHolder)
            {
                desc.props.emplace_back(prop->name, prop->type, prop->valueOffset);
            }
        }
    }
}

void App::ObjectRegistry::RestoreSnapshot()
{
    std::unique_lock lock1(s_registryLock);
    std::unique_lock lock2(s_snapshotLock);

    for (auto& weak : s_objects)
    {
        if (weak.Expired())
            continue;

        if (!weak.instance->GetType()->IsA(s_IScriptableType))
            continue;

        auto instance = reinterpret_cast<Red::IScriptable*>(weak.instance);
        auto oldHolder = instance->valueHolder;

        if (!oldHolder)
            continue;

        auto cls = instance->GetType();
        auto it = s_snapshot.find(cls->GetName());

        if (it == s_snapshot.end())
            continue;

        instance->valueHolder = nullptr;
        auto newHolder = instance->GetValueHolder();

        for (auto& oldProp : it.value().props)
        {
            auto newProp = cls->GetProperty(oldProp.name);

            if (newProp && newProp->flags.inValueHolder && newProp->type == oldProp.type)
            {
                newProp->type->Assign(GetValuePtr(newHolder, newProp->valueOffset),
                                      GetValuePtr(oldHolder, oldProp.valueOffset));
            }

            oldProp.type->Destruct(GetValuePtr(oldHolder, oldProp.valueOffset));
        }
    }

    s_snapshot.clear();

    Shrink("snapshot restore");
}

void App::ObjectRegistry::Shrink(const char* aReason)
{
    const auto generation = s_shrinkGeneration.fetch_add(1, std::memory_order_relaxed) + 1;
    const auto startedAt = GetTimestamp();
    const auto originalSize = s_objects.size();

    s_shrinkOwnerThreadID.store(GetCurrentThreadId(), std::memory_order_relaxed);
    s_shrinkStartedAt.store(startedAt, std::memory_order_relaxed);
    s_shrinkTotal.store(originalSize, std::memory_order_relaxed);
    s_shrinkProcessed.store(0, std::memory_order_relaxed);
    s_shrinkExpired.store(0, std::memory_order_relaxed);
    s_shrinkSurvivors.store(0, std::memory_order_relaxed);
    s_shrinkReleaseTotal.store(0, std::memory_order_relaxed);
    s_shrinkReleased.store(0, std::memory_order_relaxed);
    s_shrinkCurrentIndex.store(0, std::memory_order_relaxed);
    s_shrinkCurrentObject.store(0, std::memory_order_relaxed);
    s_shrinkCurrentRefCount.store(0, std::memory_order_relaxed);
    s_shrinkPhase.store(ShrinkPhase::Scanning, std::memory_order_release);

    LogInfo("[ObjectRegistry] Shrink #{} started: reason={} objects={} ownerThread={} createdObjects={} waiters={}.",
            generation, aReason, originalSize, s_shrinkOwnerThreadID.load(std::memory_order_relaxed),
            s_createdObjects.load(std::memory_order_relaxed), s_registryWaiters.load(std::memory_order_relaxed));

    size_t writeIndex{};
    size_t expired{};

    for (size_t readIndex = 0; readIndex < originalSize; ++readIndex)
    {
        auto& weak = s_objects[readIndex];

        // Publish the element before either Expired() or move assignment can stop making progress.
        s_shrinkCurrentIndex.store(readIndex, std::memory_order_relaxed);
        s_shrinkCurrentObject.store(reinterpret_cast<uintptr_t>(weak.instance), std::memory_order_relaxed);
        s_shrinkCurrentRefCount.store(reinterpret_cast<uintptr_t>(weak.refCount), std::memory_order_relaxed);

        if (weak.Expired())
        {
            ++expired;
        }
        else
        {
            if (writeIndex != readIndex)
            {
                s_objects[writeIndex] = std::move(weak);
            }
            ++writeIndex;
        }

        s_shrinkExpired.store(expired, std::memory_order_relaxed);
        s_shrinkSurvivors.store(writeIndex, std::memory_order_relaxed);
        s_shrinkProcessed.store(readIndex + 1, std::memory_order_relaxed);
    }

    const auto releaseTotal = originalSize - writeIndex;
    s_shrinkReleaseTotal.store(releaseTotal, std::memory_order_relaxed);
    s_shrinkReleased.store(0, std::memory_order_relaxed);
    s_shrinkPhase.store(ShrinkPhase::Releasing, std::memory_order_release);

    while (s_objects.size() > writeIndex)
    {
        const auto currentIndex = s_objects.size() - 1;
        s_shrinkCurrentIndex.store(currentIndex, std::memory_order_relaxed);
        s_shrinkCurrentObject.store(reinterpret_cast<uintptr_t>(s_objects.back().instance), std::memory_order_relaxed);
        s_shrinkCurrentRefCount.store(reinterpret_cast<uintptr_t>(s_objects.back().refCount),
                                      std::memory_order_relaxed);
        s_objects.pop_back();
        s_shrinkReleased.store(originalSize - s_objects.size(), std::memory_order_relaxed);
    }

    const auto elapsed = GetTimestamp() - startedAt;
    s_registrySize.store(s_objects.size(), std::memory_order_relaxed);
    s_shrinkCurrentObject.store(0, std::memory_order_relaxed);
    s_shrinkCurrentRefCount.store(0, std::memory_order_relaxed);
    s_shrinkPhase.store(ShrinkPhase::Idle, std::memory_order_release);

    LogInfo("[ObjectRegistry] Shrink #{} completed in {}ms: before={} expired={} survivors={} waiters={}.", generation,
            elapsed, originalSize, expired, s_objects.size(), s_registryWaiters.load(std::memory_order_relaxed));

    if (s_objects.size() >= MaxNumObjects - 1)
    {
        LogWarning(
            "[ObjectRegistry] Shrink #{} left {} survivors at the capacity threshold; every new handle will trigger "
            "another full shrink.",
            generation, s_objects.size());
    }
}
