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
    __except (1)
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
    PEPROCESS pEprocess = NULL;
    NTSTATUS ntStatus = PsLookupProcessByProcessId(ULongToHandle(pid), &pEprocess);
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("PsLookupProcessByProcessId failed, ntStatus: 0x%x", ntStatus);
        return ntStatus;
    }

    KAPC_STATE apcState;
    KeStackAttachProcess(pEprocess, &apcState);

    PMDL pMdl = IoAllocateMdl(pUserDst, writeLen, FALSE, FALSE, NULL);
    if (NULL == pMdl)
    {
        LOG_ERROR("IoAllocateMdl failed");
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(pEprocess);
        return STATUS_UNSUCCESSFUL;
    }

    __try
    {
        MmProbeAndLockPages(pMdl, KernelMode, IoWriteAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        LOG_ERROR("Trigger EXCEPTION_EXECUTE_HANDLER, exception: 0x%x", GetExceptionCode());
        IoFreeMdl(pMdl);
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(pEprocess);
        return STATUS_UNSUCCESSFUL;
    }

    PVOID pKernelDst = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
    if (NULL == pKernelDst)
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
        MmUnmapLockedPages(pKernelDst, pMdl);
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
        ProbeOutputBytes(pKernelDst, writeLen);
        RtlCopyMemory(pKernelDst, pUserSrc, writeLen);
    }
    __except (1)
    {
        LOG_ERROR("Trigger Exception 0x%x,", GetExceptionCode());
        MmUnmapLockedPages(pKernelDst, pMdl);
        MmUnlockPages(pMdl);
        IoFreeMdl(pMdl);
        ObDereferenceObject(pEprocess);
        return STATUS_UNSUCCESSFUL;
    }

    MmUnmapLockedPages(pKernelDst, pMdl);
    MmUnlockPages(pMdl);
    IoFreeMdl(pMdl);
    ObDereferenceObject(pEprocess);

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
