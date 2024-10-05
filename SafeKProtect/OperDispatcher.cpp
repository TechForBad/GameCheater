#include "OperDispatcher.h"

NTSTATUS OperDispatcher::DispatchOper(IN OUT COMM::PMSG pMsg)
{
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

    switch (pMsg->oper)
    {
    case COMM::Oper_MemoryRead:
    {
        ntStatus = ReadProcessMemory(
            pMsg->input_MemoryRead.pid,
            pMsg->input_MemoryRead.pUserSrc,
            pMsg->input_MemoryRead.readLen,
            pMsg->input_MemoryRead.pUserDst
        );
        break;
    }
    case COMM::Oper_MemoryWrite:
    {
        ntStatus = WriteProcessMemory(
            pMsg->input_MemoryWrite.pUserSrc,
            pMsg->input_MemoryWrite.writeLen,
            pMsg->input_MemoryWrite.pid,
            pMsg->input_MemoryWrite.pUserDst
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

NTSTATUS OperDispatcher::ReadProcessMemory(DWORD pid, PBYTE pUserSrc, ULONG readLen, PBYTE pUserDst)
{
    PEPROCESS pEprocess = NULL;
    NTSTATUS ntStatus = PsLookupProcessByProcessId(ULongToHandle(pid), &pEprocess);
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("PsLookupProcessByProcessId failed, ntStatus: 0x%x", ntStatus);
        return ntStatus;
    }

    KeAttachProcess(pEprocess);

    PMDL pMdl = IoAllocateMdl(pUserSrc, readLen, FALSE, FALSE, NULL);
    if (NULL == pMdl)
    {
        LOG_ERROR("IoAllocateMdl failed");
        KeDetachProcess();
        ObDereferenceObject(pEprocess);
        return NULL;
    }

    __try
    {
        MmProbeAndLockPages(pMdl, KernelMode, IoReadAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        LOG_ERROR("Trigger EXCEPTION_EXECUTE_HANDLER, exception: 0x%x", GetExceptionCode());
        IoFreeMdl(pMdl);
        KeDetachProcess();
        ObDereferenceObject(pEprocess);
        return NULL;
    }

    PVOID pKernelSrc = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
    if (NULL == pKernelSrc)
    {
        LOG_ERROR("MmMapLockedPagesSpecifyCache failed");
        MmUnlockPages(pMdl);
        IoFreeMdl(pMdl);
        KeDetachProcess();
        ObDereferenceObject(pEprocess);
        return NULL;
    }

    ntStatus = MmProtectMdlSystemAddress(pMdl, PAGE_READWRITE);
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("MmProtectMdlSystemAddress failed");
        MmUnmapLockedPages(pKernelSrc, pMdl);
        MmUnlockPages(pMdl);
        IoFreeMdl(pMdl);
        KeDetachProcess();
        ObDereferenceObject(pEprocess);
        return NULL;
    }

    KeDetachProcess();

    RtlCopyMemory(pUserDst, pKernelSrc, readLen);

    MmUnmapLockedPages(pKernelSrc, pMdl);
    MmUnlockPages(pMdl);
    IoFreeMdl(pMdl);
    ObDereferenceObject(pEprocess);

    return ntStatus;
}

NTSTATUS OperDispatcher::WriteProcessMemory(PBYTE pUserSrc, ULONG writeLen, DWORD pid, PBYTE pUserDst)
{
    PEPROCESS pEprocess = NULL;
    NTSTATUS ntStatus = PsLookupProcessByProcessId(ULongToHandle(pid), &pEprocess);
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("PsLookupProcessByProcessId failed, ntStatus: 0x%x", ntStatus);
        return ntStatus;
    }

    KeAttachProcess(pEprocess);

    PMDL pMdl = IoAllocateMdl(pUserDst, writeLen, FALSE, FALSE, NULL);
    if (NULL == pMdl)
    {
        LOG_ERROR("IoAllocateMdl failed");
        KeDetachProcess();
        ObDereferenceObject(pEprocess);
        return NULL;
    }

    __try
    {
        MmProbeAndLockPages(pMdl, KernelMode, IoWriteAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        LOG_ERROR("Trigger EXCEPTION_EXECUTE_HANDLER, exception: 0x%x", GetExceptionCode());
        IoFreeMdl(pMdl);
        KeDetachProcess();
        ObDereferenceObject(pEprocess);
        return NULL;
    }

    PVOID pKernelDst = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
    if (NULL == pKernelDst)
    {
        LOG_ERROR("MmMapLockedPagesSpecifyCache failed");
        MmUnlockPages(pMdl);
        IoFreeMdl(pMdl);
        KeDetachProcess();
        ObDereferenceObject(pEprocess);
        return NULL;
    }

    ntStatus = MmProtectMdlSystemAddress(pMdl, PAGE_READWRITE);
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("MmProtectMdlSystemAddress failed");
        MmUnmapLockedPages(pKernelDst, pMdl);
        MmUnlockPages(pMdl);
        IoFreeMdl(pMdl);
        KeDetachProcess();
        ObDereferenceObject(pEprocess);
        return NULL;
    }

    KeDetachProcess();

    RtlCopyMemory(pUserSrc, pKernelDst, writeLen);

    MmUnmapLockedPages(pKernelDst, pMdl);
    MmUnlockPages(pMdl);
    IoFreeMdl(pMdl);
    ObDereferenceObject(pEprocess);

    return ntStatus;
}
