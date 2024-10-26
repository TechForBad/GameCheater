#include "vmUtils.h"

#include "../HyperPlatform/common.h"
#include "../HyperPlatform/global_object.h"
#include "../HyperPlatform/hotplug_callback.h"
#include "../HyperPlatform/log.h"
#include "../HyperPlatform/power_callback.h"
#include "../HyperPlatform/util.h"
#include "../HyperPlatform/vm.h"
#include "../HyperPlatform/performance.h"

NTSTATUS VmUtils::InitVm()
{
    static const wchar_t kLogFilePath[] = L"\\SystemRoot\\HyperPlatform.log";
    static const auto kLogLevel =
        (IsReleaseBuild()) ? kLogPutLevelInfo | kLogOptDisableFunctionName
        : kLogPutLevelDebug | kLogOptDisableFunctionName;

    PDRIVER_OBJECT pDriverObject = NULL;

    NTSTATUS status = STATUS_UNSUCCESSFUL;

    // Request NX Non-Paged Pool when available
    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    // Initialize log functions
    bool need_reinitialization = false;
    status = LogInitialization(kLogLevel, kLogFilePath);
    if (status == STATUS_REINITIALIZATION_NEEDED)
    {
        need_reinitialization = true;
    }
    else if (!NT_SUCCESS(status))
    {
        return status;
    }

    // Test if the system is supported
    if (!DriverpIsSuppoetedOS())
    {
        LogTermination();
        return STATUS_CANCELLED;
    }

    // Initialize global variables
    status = GlobalObjectInitialization();
    if (!NT_SUCCESS(status))
    {
        LogTermination();
        return status;
    }

    // Initialize perf functions
    status = PerfInitialization();
    if (!NT_SUCCESS(status))
    {
        GlobalObjectTermination();
        LogTermination();
        return status;
    }

    // Initialize utility functions
    status = UtilInitialization(pDriverObject);
    if (!NT_SUCCESS(status))
    {
        PerfTermination();
        GlobalObjectTermination();
        LogTermination();
        return status;
    }

    // Initialize power callback
    status = PowerCallbackInitialization();
    if (!NT_SUCCESS(status))
    {
        UtilTermination();
        PerfTermination();
        GlobalObjectTermination();
        LogTermination();
        return status;
    }

    // Initialize hot-plug callback
    status = HotplugCallbackInitialization();
    if (!NT_SUCCESS(status))
    {
        PowerCallbackTermination();
        UtilTermination();
        PerfTermination();
        GlobalObjectTermination();
        LogTermination();
        return status;
    }

    // Virtualize all processors
    status = VmInitialization();
    if (!NT_SUCCESS(status))
    {
        HotplugCallbackTermination();
        PowerCallbackTermination();
        UtilTermination();
        PerfTermination();
        GlobalObjectTermination();
        LogTermination();
        return status;
    }

    // Register re-initialization for the log functions if needed
    if (need_reinitialization)
    {
        LogRegisterReinitialization(pDriverObject);
    }

    HYPERPLATFORM_LOG_INFO("The VMM has been installed.");
    return status;
}

VOID VmUtils::UnInitVm()
{
    VmTermination();
    HotplugCallbackTermination();
    PowerCallbackTermination();
    UtilTermination();
    PerfTermination();
    GlobalObjectTermination();
    LogTermination();
}

BOOL VmUtils::DriverpIsSuppoetedOS()
{
    RTL_OSVERSIONINFOW os_version = {};
    auto status = RtlGetVersion(&os_version);
    if (!NT_SUCCESS(status))
    {
        return false;
    }
    if (os_version.dwMajorVersion != 6 && os_version.dwMajorVersion != 10)
    {
        return false;
    }
    // 4-gigabyte tuning (4GT) should not be enabled
    if (!IsX64() &&
        reinterpret_cast<ULONG_PTR>(MmSystemRangeStart) != 0x80000000)
    {
        return false;
    }
    return true;
}
