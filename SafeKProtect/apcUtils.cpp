#include "apcUtils.h"

static void NTAPI KernelKernelRoutine2(
    _In_ PKAPC Apc,
    _Inout_ PKNORMAL_ROUTINE* NormalRoutine,
    _Inout_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2
)
{
    ExFreePoolWithTag(Apc, MEM_TAG);

    ULONG_PTR iswow64;
    if (ZwQueryInformationProcess(ZwCurrentProcess(), ProcessWow64Information, &iswow64, sizeof(iswow64), NULL) == STATUS_SUCCESS)
    {
#if (NTDDI_VERSION >= NTDDI_VISTA)	
        if (iswow64)
        {
            PsWrapApcWow64Thread((PVOID*)NormalContext, (PVOID*)NormalRoutine);
        }
#endif
    }
}

static void NTAPI KernelKernelRoutine(
    _In_ PKAPC Apc,
    _Inout_ PKNORMAL_ROUTINE* NormalRoutine,
    _Inout_ PVOID* NormalContext,                               // 用户态shellcode的参数地址
    _Inout_ PVOID* SystemArgument1,                             // 需要执行的用户态shellcode地址
    _Inout_ PVOID* SystemArgument2
)
{
    LOG_INFO("Create User Mode APC, shellcode addr: %p, param: %p", (PVOID)*SystemArgument1, (PVOID)*NormalContext);

    // kernelmode apc, always gets executed
    ExFreePoolWithTag(Apc, MEM_TAG);

    PKAPC userModeApc = (PKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), MEM_TAG);
    if (NULL == userModeApc)
    {
        return;
    }

    KeInitializeApc(
        userModeApc,                                            // Apc
        (PKTHREAD)PsGetCurrentThread(),                         // Thread
        OriginalApcEnvironment,                                 // Environment
        (PKKERNEL_ROUTINE)KernelKernelRoutine2,                 // KernelRoutine
        NULL,                                                   // RundownRoutine
        (PKNORMAL_ROUTINE) * (PUINT_PTR)SystemArgument1,        // NormalRoutine
        UserMode,                                               // ApcMode
        (PVOID) * (PUINT_PTR)NormalContext                      // NormalContext
    );

    KeInsertQueueApc(
        userModeApc,                                            // Apc
        (PVOID) * (PUINT_PTR)SystemArgument1,                   // SystemArgument1
        (PVOID) * (PUINT_PTR)SystemArgument2,                   // SystemArgument2
        0                                                       // Increment
    );

    // wait in usermode (so interruptable by a usermode apc)
    LARGE_INTEGER Timeout;
    Timeout.QuadPart = 0;
    KeDelayExecutionThread(UserMode, TRUE, &Timeout);

    return;
}

static VOID NTAPI KernelRundownRoutine(
    _In_ PKAPC Apc
)
{
    ExFreePoolWithTag(Apc, MEM_TAG);
}

static void KernelNormalRoutine(PVOID arg1, PVOID arg2, PVOID arg3)
{
    return;
}

NTSTATUS ApcUtils::CreateRemoteAPC(IN PETHREAD pEthread, IN PVOID addrToExe, IN ULONG64 parameter)
{
    PKAPC kernelModeApc = (PKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), MEM_TAG);
    if (NULL == kernelModeApc)
    {
        LOG_ERROR("ExAllocatePoolWithTag failed");
        return STATUS_UNSUCCESSFUL;
    }

    KeInitializeApc(
        kernelModeApc,                                  // Apc
        pEthread,                                       // Thread
        KAPC_ENVIRONMENT::OriginalApcEnvironment,       // Environment
        KernelKernelRoutine,                            // KernelRoutine
        KernelRundownRoutine,                           // RundownRoutine
        KernelNormalRoutine,                            // NormalRoutine
        KernelMode,                                     // ApcMode
        (PVOID)parameter                                // NormalContext
    );

    if (!KeInsertQueueApc(
        kernelModeApc,                                  // Apc
        addrToExe,                                      // SystemArgument1
        addrToExe,                                      // SystemArgument2
        0                                               // Increment
    ))
    {
        LOG_ERROR("KeInsertQueueApc failed");
        ExFreePoolWithTag(kernelModeApc, MEM_TAG);
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS ApcUtils::RemoteCallBySwitchContext(PSET_CONTEXT_CALL_INFORMATION callInfo)
{
    KeInitializeEvent(&callInfo->kEvent, NotificationEvent, FALSE);

    PKAPC kernelModeApc = (PKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), MEM_TAG);
    if (NULL == kernelModeApc)
    {
        LOG_ERROR("ExAllocatePoolWithTag failed");
        return STATUS_UNSUCCESSFUL;
    }

    KeInitializeApc(kernelModeApc, callInfo->pTargetEthread, OriginalApcEnvironment, SetCtxApcCallback, NULL, NULL, KernelMode, NULL);

    this->CallInfo = callInfo;

    if (!KeInsertQueueApc(kernelModeApc, this, 0, 2))
    {
        LOG_ERROR("KeInsertQueueApc failed");
        ExFreePoolWithTag(kernelModeApc, MEM_TAG);
        return STATUS_NOT_CAPABLE;
    }

    NTSTATUS ntStatus = KeWaitForSingleObject(&callInfo->kEvent, Executive, KernelMode, FALSE, NULL);
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("KeWaitForSingleObject failed, ntStatus: 0x%x", ntStatus);
        return ntStatus;
    }

    return STATUS_SUCCESS;
}
