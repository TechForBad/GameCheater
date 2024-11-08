#include "apcUtils.h"

static void NTAPI KernelKernelRoutine2(
    _In_ PKAPC Apc,
    _Inout_ PKNORMAL_ROUTINE* NormalRoutine,
    _Inout_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2
)
{
    KFree(Apc);

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
    KFree(Apc);

    PKAPC userModeApc = (PKAPC)KAlloc(sizeof(KAPC));
    if (NULL == userModeApc)
    {
        LOG_ERROR("KAlloc failed");
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
    KFree(Apc);
}

static void KernelNormalRoutine(PVOID arg1, PVOID arg2, PVOID arg3)
{
    return;
}

NTSTATUS ApcUtils::CreateRemoteAPC(IN PETHREAD pEthread, IN PVOID addrToExe, IN ULONG64 parameter)
{
    PKAPC kernelModeApc = (PKAPC)KAlloc(sizeof(KAPC));
    if (NULL == kernelModeApc)
    {
        LOG_ERROR("KAlloc failed");
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
        KFree(kernelModeApc);
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS ApcUtils::RemoteCallMessageBoxBySetCtx(DWORD pid)
{
    PEPROCESS pEprocess = NULL;
    NTSTATUS ntStatus = PsLookupProcessByProcessId(ULongToHandle(pid), &pEprocess);
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("PsLookupProcessByProcessId failed, ntStatus: 0x%x", ntStatus);
        return ntStatus;
    }

    KAPC_STATE apcState;
    KeStackAttachProcess(pEprocess, &apcState);

    // 获取一个可以alertable的线程
    PETHREAD pTargetEthread = NULL;
    ntStatus = ProcessUtils::FindProcessEthread(pEprocess, &pTargetEthread);
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("FindProcessEthread failed, ntStatus: 0x%x", ntStatus);
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(pEprocess);
        return ntStatus;
    }

    // 获取目标函数地址
    PVOID hUser32 = GetModuleHandle("user32.dll");
    if (NULL == hUser32)
    {
        LOG_ERROR("GetModuleHandle failed");
        ObDereferenceObject(pTargetEthread);
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(pEprocess);
        return STATUS_UNSUCCESSFUL;
    }
    PVOID fun_MessageBoxW = GetProcAddress(hUser32, "MessageBoxW");
    if (NULL == fun_MessageBoxW)
    {
        LOG_ERROR("GetProcAddress failed");
        ObDereferenceObject(pTargetEthread);
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(pEprocess);
        return STATUS_UNSUCCESSFUL;
    }

    KeUnstackDetachProcess(&apcState);

    // 初始化调用信息
    PSET_CONTEXT_CALL_INFO callInfo = (PSET_CONTEXT_CALL_INFO)KAlloc(0x1000);
    if (NULL == callInfo)
    {
        LOG_ERROR("KAlloc failed");
        ObDereferenceObject(pTargetEthread);
        ObDereferenceObject(pEprocess);
        return STATUS_UNSUCCESSFUL;
    }

    callInfo->pTargetEthread = pTargetEthread;
    callInfo->userFunction = fun_MessageBoxW;
    callInfo->paramCnt = 4;
    callInfo->param[0].asU64 = 0;       // MB_OK
    callInfo->param[1].asU64 = 0;
    callInfo->param[2].asU64 = 0;
    callInfo->param[3].asU64 = 0x40;    // MB_ICONINFORMATION;
    callInfo->fun_PreCallKernelRoutine = [](PSET_CONTEXT_CALL_INFO callInfo)
    {
        PWCH UserStrMsg = (PWCH)UAlloc(0x1000);
        PWCH UserStrTitle = (PWCH)UAlloc(0x1000);
        wcscpy(UserStrMsg, L"Hi, I'm Pipi");
        wcscpy(UserStrTitle, L"来自远程Call");

        callInfo->param[1].asU64 = (ULONG64)UserStrMsg;
        callInfo->param[2].asU64 = (ULONG64)UserStrTitle;
    };
    callInfo->fun_PostCallKernelRoutine = [](PSET_CONTEXT_CALL_INFO callInfo)
    {
        UFree((PVOID)callInfo->param[1].asU64);
        UFree((PVOID)callInfo->param[2].asU64);
    };

    // 远程调用
    SetCtxCallTask setCtxCallTask(callInfo);
    ntStatus = setCtxCallTask.Call();

    KFree(callInfo);
    ObDereferenceObject(pTargetEthread);
    ObDereferenceObject(pEprocess);

    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("Call failed");
        return ntStatus;
    }

    return STATUS_SUCCESS;
}
