#include "vmUtils.h"

#include "../HyperPlatform/common.h"
#include "../HyperPlatform/global_object.h"
#include "../HyperPlatform/hotplug_callback.h"
#include "../HyperPlatform/power_callback.h"
#include "../HyperPlatform/util.h"
#include "../HyperPlatform/vm.h"
#include "../HyperPlatform/performance.h"

BOOL VmUtils::is_vm_init_{ FALSE };

NTSTATUS VmUtils::InitVm()
{
    if (is_vm_init_)
    {
        LOG_INFO("vm has been inited");
        return STATUS_SUCCESS;
    }

    PDRIVER_OBJECT pDriverObject = GetDriverObject(L"\\Driver\\disk");
    if (NULL == pDriverObject)
    {
        LOG_ERROR("GetDriverObject failed");
        return STATUS_UNSUCCESSFUL;
    }

    // Request NX Non-Paged Pool when available
    // ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    // Test if the system is supported
    if (!DriverpIsSuppoetedOS())
    {
        LOG_ERROR("DriverpIsSuppoetedOS failed");
        return STATUS_CANCELLED;
    }

    // Initialize global variables
    NTSTATUS ntStatus = GlobalObjectInitialization();
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("GlobalObjectInitialization failed");
        return ntStatus;
    }

    // Initialize perf functions
    ntStatus = PerfInitialization();
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("PerfInitialization failed");
        GlobalObjectTermination();
        return ntStatus;
    }

    // Initialize utility functions
    ntStatus = UtilInitialization(pDriverObject);
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("UtilInitialization failed");
        PerfTermination();
        GlobalObjectTermination();
        return ntStatus;
    }

    // Initialize power callback
    ntStatus = PowerCallbackInitialization();
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("PowerCallbackInitialization failed");
        UtilTermination();
        PerfTermination();
        GlobalObjectTermination();
        return ntStatus;
    }

    // Initialize hot-plug callback
    ntStatus = HotplugCallbackInitialization();
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("HotplugCallbackInitialization failed");
        PowerCallbackTermination();
        UtilTermination();
        PerfTermination();
        GlobalObjectTermination();
        return ntStatus;
    }

    // Virtualize all processors
    ntStatus = VmInitialization();
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("VmInitialization failed");
        HotplugCallbackTermination();
        PowerCallbackTermination();
        UtilTermination();
        PerfTermination();
        GlobalObjectTermination();
        return ntStatus;
    }

    is_vm_init_ = TRUE;

    LOG_INFO("The VMM has been installed.");
    return ntStatus;
}

VOID VmUtils::UnInitVm()
{
    if (!is_vm_init_)
    {
        LOG_INFO("vm is not inited, uninit vm failed");
        return;
    }

    VmTermination();
    HotplugCallbackTermination();
    PowerCallbackTermination();
    UtilTermination();
    PerfTermination();
    GlobalObjectTermination();

    is_vm_init_ = FALSE;

    LOG_INFO("The VMM has been uninstalled.");
}

PDRIVER_OBJECT VmUtils::GetDriverObject(PCWSTR driverName)
{
    UNICODE_STRING ustrDriverName;
    RtlInitUnicodeString(&ustrDriverName, driverName);

    PDRIVER_OBJECT pDriverObject;
    NTSTATUS ntStatus = ObReferenceObjectByName(
        &ustrDriverName, 0, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&pDriverObject);
    if (!NT_SUCCESS(ntStatus))
    {
        return NULL;
    }

    return pDriverObject;
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
