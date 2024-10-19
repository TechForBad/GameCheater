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

NTSTATUS ApcUtils::RemoteCallMessageBoxBySetCtx(DWORD pid, LPCWSTR dllPath)
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
    // PVOID fun_MsgBoxW = MemoryUtils::GetModuleExportAddress("dbghelp.dll", "MiniDumpWriteDump");
    PVOID fun_MsgBoxW = MemoryUtils::GetModuleExportAddress("user32.dll", "MessageBoxW");
    if (NULL == fun_MsgBoxW)
    {
        LOG_ERROR("GetModuleExportAddress failed");
        ObDereferenceObject(pTargetEthread);
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(pEprocess);
        return STATUS_UNSUCCESSFUL;
    }

    KeUnstackDetachProcess(&apcState);

    // 初始化调用信息
    PSET_CONTEXT_CALL_INFO callInfo = (PSET_CONTEXT_CALL_INFO)ExAllocatePoolWithTag(NonPagedPool, 0x1000, MEM_TAG);
    if (NULL == callInfo)
    {
        LOG_ERROR("ExAllocatePoolWithTag failed");
        ObDereferenceObject(pTargetEthread);
        ObDereferenceObject(pEprocess);
        return STATUS_UNSUCCESSFUL;
    }

    /*
    using Fun_MiniDumpWriteDump = BOOL(__stdcall*)(
        _In_ HANDLE hProcess,
        _In_ DWORD ProcessId,
        _In_ HANDLE hFile,
        _In_ MINIDUMP_TYPE DumpType,
        _In_opt_ PVOID ExceptionParam,
        _In_opt_ PVOID UserStreamParam,
        _In_opt_ PVOID CallbackParam
        );

    MiniDumpWriteDump(
        hProcess,
        pid,
        hDumpFile,
        MiniDumpWithFullMemory,  // full dump
        NULL,
        NULL,
        NULL
    );
    */
    callInfo->pTargetEthread = pTargetEthread;
    callInfo->userFunction = fun_MsgBoxW;
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

    KeInitializeEvent(&callInfo->kEvent, NotificationEvent, FALSE);

    // 远程调用
    SetCtxCallTask setCtxCallTask(callInfo);
    ntStatus = setCtxCallTask.Call();

    ExFreePoolWithTag(callInfo, MEM_TAG);
    ObDereferenceObject(pTargetEthread);
    ObDereferenceObject(pEprocess);

    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("Call failed");
        return ntStatus;
    }

    return STATUS_SUCCESS;
}
