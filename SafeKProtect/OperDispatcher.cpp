#include "OperDispatcher.h"

NTSTATUS OperDispatcher::DispatchOper(IN OUT COMM::PCMSG pMsg)
{
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

    switch (pMsg->oper)
    {
    case COMM::Oper_ProcessMemoryRead:
    {
        ntStatus = ReadProcessMemory(
            pMsg->input_MemoryRead.pid,
            pMsg->input_MemoryRead.pUserSrc,
            pMsg->input_MemoryRead.readLen,
            pMsg->input_MemoryRead.pUserDst
        );
        break;
    }
    case COMM::Oper_ProcessMemoryWrite:
    {
        ntStatus = WriteProcessMemory(
            pMsg->input_MemoryWrite.pUserSrc,
            pMsg->input_MemoryWrite.writeLen,
            pMsg->input_MemoryWrite.pid,
            pMsg->input_MemoryWrite.pUserDst
        );
        break;
    }
    case COMM::Oper_ProcessModuleBase:
    {
        ntStatus = GetProcessModuleBase(
            pMsg->input_ModuleBase.pid,
            pMsg->input_ModuleBase.moduleName,
            &pMsg->output_ModuleBase.moduleBase,
            &pMsg->output_ModuleBase.moduleSize
        );
        break;
    }
    case COMM::Oper_CreateAPC:
    {
        ntStatus = CreateRemoteAPC(
            pMsg->input_CreateAPC.tid,
            pMsg->input_CreateAPC.addrToExe
        );
        break;
    }
    case COMM::Oper_AllocProcessMem:
    {
        ntStatus = AllocProcessMem(
            pMsg->input_AllocProcessMem.pid,
            pMsg->input_AllocProcessMem.memSize,
            pMsg->input_AllocProcessMem.allocationType,
            pMsg->input_AllocProcessMem.protect,
            &pMsg->output_AllocProcessMem.moduleBase
        );
        break;
    }
    case COMM::Oper_SuspendTargetThread:
    {
        ntStatus = SuspendTargetThread(
            pMsg->input_SuspendTargetThread.tid
        );
        break;
    }
    case COMM::Oper_ResumeTargetThread:
    {
        ntStatus = ResumeTargetThread(
            pMsg->input_ResumeTargetThread.tid
        );
        break;
    }
    case COMM::Oper_SuspendTargetProcess:
    {
        ntStatus = SuspendTargetProcess(
            pMsg->input_SuspendTargetProcess.pid
        );
        break;
    }
    case COMM::Oper_ResumeTargetProcess:
    {
        ntStatus = ResumeTargetProcess(
            pMsg->input_ResumeTargetProcess.pid
        );
        break;
    }
    case COMM::Oper_GetHandleForProcessID:
    {
        ntStatus = GetHandleForProcessID(
            pMsg->input_GetHandleForProcessID.pid,
            &pMsg->output_GetHandleForProcessID.hProcHandle
        );
        break;
    }
    default:
    {
        LOG_ERROR("Unknown OperCode: 0x%x", pMsg->oper);
        break;
    }
    }

    return ntStatus;
}

NTSTATUS OperDispatcher::ReadProcessMemory(IN DWORD pid, IN PBYTE pUserSrc, IN ULONG readLen, OUT PBYTE pUserDst)
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

    PMDL pMdl = IoAllocateMdl(pUserSrc, readLen, FALSE, FALSE, NULL);
    if (NULL == pMdl)
    {
        LOG_ERROR("IoAllocateMdl failed");
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(pEprocess);
        return STATUS_UNSUCCESSFUL;
    }

    __try
    {
        MmProbeAndLockPages(pMdl, KernelMode, IoReadAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        LOG_ERROR("Trigger EXCEPTION_EXECUTE_HANDLER, exception: 0x%x", GetExceptionCode());
        IoFreeMdl(pMdl);
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(pEprocess);
        return STATUS_UNSUCCESSFUL;
    }

    PVOID pKernelSrc = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
    if (NULL == pKernelSrc)
    {
        LOG_ERROR("MmMapLockedPagesSpecifyCache failed");
        MmUnlockPages(pMdl);
        IoFreeMdl(pMdl);
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(pEprocess);
        return STATUS_UNSUCCESSFUL;
    }

    ntStatus = MmProtectMdlSystemAddress(pMdl, PAGE_READWRITE);
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("MmProtectMdlSystemAddress failed");
        MmUnmapLockedPages(pKernelSrc, pMdl);
        MmUnlockPages(pMdl);
        IoFreeMdl(pMdl);
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(pEprocess);
        return ntStatus;
    }

    KeUnstackDetachProcess(&apcState);

    // 拷贝数据
    __try
    {
        ProbeOutputBytes(pUserDst, readLen);
        RtlCopyMemory(pUserDst, pKernelSrc, readLen);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        LOG_ERROR("Trigger Exception 0x%x,", GetExceptionCode());
        MmUnmapLockedPages(pKernelSrc, pMdl);
        MmUnlockPages(pMdl);
        IoFreeMdl(pMdl);
        ObDereferenceObject(pEprocess);
        return STATUS_UNSUCCESSFUL;
    }

    MmUnmapLockedPages(pKernelSrc, pMdl);
    MmUnlockPages(pMdl);
    IoFreeMdl(pMdl);
    ObDereferenceObject(pEprocess);

    return STATUS_SUCCESS;
}

NTSTATUS OperDispatcher::WriteProcessMemory(IN PBYTE pUserSrc, IN ULONG writeLen, IN DWORD pid, OUT PBYTE pUserDst)
{
    PMDL pMdl = IoAllocateMdl(pUserSrc, writeLen, FALSE, FALSE, NULL);
    if (NULL == pMdl)
    {
        LOG_ERROR("IoAllocateMdl failed");
        return STATUS_UNSUCCESSFUL;
    }

    __try
    {
        MmProbeAndLockPages(pMdl, KernelMode, IoReadAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        LOG_ERROR("Trigger EXCEPTION_EXECUTE_HANDLER, exception: 0x%x", GetExceptionCode());
        IoFreeMdl(pMdl);
        return STATUS_UNSUCCESSFUL;
    }

    PVOID pKernelSrc = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
    if (NULL == pKernelSrc)
    {
        LOG_ERROR("MmMapLockedPagesSpecifyCache failed");
        MmUnlockPages(pMdl);
        IoFreeMdl(pMdl);
        return STATUS_UNSUCCESSFUL;
    }

    NTSTATUS ntStatus = MmProtectMdlSystemAddress(pMdl, PAGE_READWRITE);
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("MmProtectMdlSystemAddress failed");
        MmUnmapLockedPages(pKernelSrc, pMdl);
        MmUnlockPages(pMdl);
        IoFreeMdl(pMdl);
        return ntStatus;
    }

    PEPROCESS pEprocess = NULL;
    ntStatus = PsLookupProcessByProcessId(ULongToHandle(pid), &pEprocess);
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("PsLookupProcessByProcessId failed, ntStatus: 0x%x", ntStatus);
        MmUnmapLockedPages(pKernelSrc, pMdl);
        MmUnlockPages(pMdl);
        IoFreeMdl(pMdl);
        return ntStatus;
    }

    KAPC_STATE apcState;
    KeStackAttachProcess(pEprocess, &apcState);

    if ((!MemoryUtils::IsAddressSafe((UINT_PTR)pUserDst)) || (!MemoryUtils::IsAddressSafe((UINT_PTR)pUserDst + writeLen - 1)))
    {
        LOG_ERROR("IsAddressSafe failed");
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(pEprocess);
        MmUnmapLockedPages(pKernelSrc, pMdl);
        MmUnlockPages(pMdl);
        IoFreeMdl(pMdl);
        return STATUS_INVALID_ADDRESS;
    }

    // 拷贝数据
    __try
    {
        RtlCopyMemory(pUserDst, pKernelSrc, writeLen);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        LOG_ERROR("Trigger Exception 0x%x,", GetExceptionCode());
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(pEprocess);
        MmUnmapLockedPages(pKernelSrc, pMdl);
        MmUnlockPages(pMdl);
        IoFreeMdl(pMdl);
        return STATUS_UNSUCCESSFUL;
    }

    KeUnstackDetachProcess(&apcState);

    ObDereferenceObject(pEprocess);
    MmUnmapLockedPages(pKernelSrc, pMdl);
    MmUnlockPages(pMdl);
    IoFreeMdl(pMdl);

    return STATUS_SUCCESS;
}

NTSTATUS OperDispatcher::GetProcessModuleBase(IN DWORD pid, IN LPCWSTR moduleName, OUT PVOID* pModuleBase, OUT PULONG moduleSize)
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

    *pModuleBase = MemoryUtils::GetProcessModuleBase(pEprocess, moduleName, moduleSize);

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(pEprocess);

    return STATUS_SUCCESS;
}

static void mykapc2(PKAPC Apc, PKNORMAL_ROUTINE NormalRoutine, PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    ULONG_PTR iswow64;

    ExFreePoolWithTag(Apc, MEM_TAG);

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

static void mykapc(PKAPC Apc, PKNORMAL_ROUTINE NormalRoutine, PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    // kernelmode apc, always gets executed
    PKAPC kApc;
    LARGE_INTEGER Timeout;

    kApc = (PKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), MEM_TAG);

    ExFreePoolWithTag(Apc, MEM_TAG);

    if (NULL == kApc)
    {
        return;
    }

    KeInitializeApc(
        kApc,
        (PKTHREAD)PsGetCurrentThread(),
        KAPC_ENVIRONMENT::OriginalApcEnvironment,
        (PKKERNEL_ROUTINE)mykapc2,
        NULL,
        (PKNORMAL_ROUTINE) * (PUINT_PTR)SystemArgument1,
        UserMode,
        (PVOID) * (PUINT_PTR)NormalContext
    );

    KeInsertQueueApc(kApc, (PVOID) * (PUINT_PTR)SystemArgument1, (PVOID) * (PUINT_PTR)SystemArgument2, 0);

    // wait in usermode (so interruptable by a usermode apc)
    Timeout.QuadPart = 0;
    KeDelayExecutionThread(UserMode, TRUE, &Timeout);

    return;
}

static void nothing(PVOID arg1, PVOID arg2, PVOID arg3)
{
    return;
}

NTSTATUS OperDispatcher::CreateRemoteAPC(IN DWORD tid, IN PVOID addrToExe)
{
    PETHREAD pEthread = NULL;
    NTSTATUS ntStatus = PsLookupThreadByThreadId(ULongToHandle(tid), &pEthread);
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("PsLookupThreadByThreadId failed, ntStatus: 0x%x", ntStatus);
        return ntStatus;
    }

    PKAPC kApc = (PKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), MEM_TAG);
    if (NULL == kApc)
    {
        LOG_ERROR("ExAllocatePoolWithTag failed");
        ObDereferenceObject(pEthread);
        return STATUS_UNSUCCESSFUL;
    }

    KeInitializeApc(
        kApc,
        pEthread,
        KAPC_ENVIRONMENT::OriginalApcEnvironment,
        (PKKERNEL_ROUTINE)mykapc,
        NULL,
        (PKNORMAL_ROUTINE)nothing,
        KernelMode,
        0
    );

    KeInsertQueueApc(kApc, addrToExe, addrToExe, 0);

    ObDereferenceObject(pEthread);
    return STATUS_SUCCESS;
}

NTSTATUS OperDispatcher::AllocProcessMem(IN DWORD pid, IN SIZE_T memSize, IN ULONG allocationType, IN ULONG protect, OUT PVOID* pModuleBase)
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

    PVOID moduleBase = NULL;
    ntStatus = ZwAllocateVirtualMemory(NtCurrentProcess(), &moduleBase, 0, &memSize, allocationType, protect);
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("ZwAllocateVirtualMemory failed, ntStatus: 0x%x", ntStatus);
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(pEprocess);
        return ntStatus;
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(pEprocess);

    *pModuleBase = moduleBase;

    return STATUS_SUCCESS;
}

NTSTATUS OperDispatcher::SuspendTargetThread(IN DWORD tid)
{
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS OperDispatcher::ResumeTargetThread(IN DWORD tid)
{
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS OperDispatcher::SuspendTargetProcess(IN DWORD pid)
{
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS OperDispatcher::ResumeTargetProcess(IN DWORD pid)
{
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS OperDispatcher::GetHandleForProcessID(IN DWORD pid, OUT PHANDLE pProcHandle)
{
    PEPROCESS pEprocess = NULL;

    __try
    {
        NTSTATUS ntStatus = PsLookupProcessByProcessId((PVOID)(UINT_PTR)(pid), &pEprocess);
        if (!NT_SUCCESS(ntStatus))
        {
            LOG_ERROR("PsLookupProcessByProcessId failed, ntStatus: 0x%x", ntStatus);
            return ntStatus;
        }

        ntStatus = ObOpenObjectByPointer(
            pEprocess,
            0,
            NULL,
            PROCESS_ALL_ACCESS,
            *PsProcessType,
            KernelMode,
            pProcHandle
        );
        if (!NT_SUCCESS(ntStatus))
        {
            LOG_ERROR("ObOpenObjectByPointer failed, ntStatus: 0x%x", ntStatus);
            ObDereferenceObject(pEprocess);
            return ntStatus;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        LOG_ERROR("Trigger Exception 0x%x,", GetExceptionCode());
        ObDereferenceObject(pEprocess);
        return STATUS_UNSUCCESSFUL;
    }

    if (pEprocess)
    {
        ObDereferenceObject(pEprocess);
    }

    return STATUS_SUCCESS;
}
