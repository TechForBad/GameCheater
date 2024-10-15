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
            pMsg->input_CreateAPC.addrToExe,
            NULL
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
    case COMM::Oper_FreeProcessMem:
    {
        ntStatus = FreeProcessMem(
            pMsg->input_FreeProcessMem.pid,
            pMsg->input_FreeProcessMem.moduleBase
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
    case COMM::Oper_ReadPhysicalMemory:
    {
        ntStatus = ReadPhysicalMemory(
            pMsg->input_ReadPhysicalMemory.pPhySrc,
            pMsg->input_ReadPhysicalMemory.readLen,
            pMsg->input_ReadPhysicalMemory.pUserDst
        );
        break;
    }
    case COMM::Oper_WritePhysicalMemory:
    {
        ntStatus = WritePhysicalMemory(
            pMsg->input_WritePhysicalMemory.pUserSrc,
            pMsg->input_WritePhysicalMemory.writeLen,
            pMsg->input_WritePhysicalMemory.pPhyDst
        );
        break;
    }
    case COMM::Oper_GetPhysicalAddress:
    {
        ntStatus = GetPhysicalAddress(
            pMsg->input_GetPhysicalAddress.pid,
            pMsg->input_GetPhysicalAddress.virtualAddress,
            &pMsg->output_GetPhysicalAddress.physicalAddress
        );
        break;
    }
    case COMM::Oper_InjectDllWithNoModuleByAPC:
    {
        ntStatus = InjectDllWithNoModuleByAPC(
            pMsg->input_InjectDllWithNoModuleByAPC.pid,
            pMsg->input_InjectDllWithNoModuleByAPC.dllPath
        );
        break;
    }
    case COMM::Oper_InjectDllWithNoModuleByEventHook:
    {
        ntStatus = InjectDllWithNoModuleByEventHook(
            pMsg->input_InjectDllWithNoModuleByEventHook.pid,
            pMsg->input_InjectDllWithNoModuleByEventHook.dllPath
        );
        break;
    }
    case COMM::Oper_ProcessCreateFullDump:
    {
        ntStatus = ProcessCreateFullDump(
            pMsg->input_ProcessCreateFullDump.pid,
            pMsg->input_ProcessCreateFullDump.dumpPath
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

NTSTATUS OperDispatcher::CreateRemoteAPC(IN DWORD tid, IN PVOID addrToExe, IN ULONG64 parameter)
{
    PETHREAD pEthread = NULL;
    NTSTATUS ntStatus = PsLookupThreadByThreadId(ULongToHandle(tid), &pEthread);
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("PsLookupThreadByThreadId failed, ntStatus: 0x%x", ntStatus);
        return ntStatus;
    }

    ntStatus = ApcUtils::CreateRemoteAPC(pEthread, addrToExe, parameter);
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("CreateRemoteAPC failed, ntStatus: 0x%x", ntStatus);
        ObDereferenceObject(pEthread);
        return ntStatus;
    }

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

NTSTATUS OperDispatcher::FreeProcessMem(IN DWORD pid, IN PVOID moduleBase)
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

    SIZE_T regionSize = 0;
    ntStatus = ZwFreeVirtualMemory(NtCurrentProcess(), &moduleBase, &regionSize, MEM_RELEASE);
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("ZwFreeVirtualMemory failed, ntStatus: 0x%x", ntStatus);
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(pEprocess);
        return ntStatus;
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(pEprocess);

    return STATUS_SUCCESS;
}

NTSTATUS OperDispatcher::SuspendTargetThread(IN DWORD tid)
{
    return ProcessUtils::SuspendTargetThread(tid);
}

NTSTATUS OperDispatcher::ResumeTargetThread(IN DWORD tid)
{
    return ProcessUtils::ResumeTargetThread(tid);
}

NTSTATUS OperDispatcher::SuspendTargetProcess(IN DWORD pid)
{
    return ProcessUtils::SuspendTargetProcess(pid);
}

NTSTATUS OperDispatcher::ResumeTargetProcess(IN DWORD pid)
{
    return ProcessUtils::ResumeTargetProcess(pid);
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

NTSTATUS OperDispatcher::ReadPhysicalMemory(IN PBYTE pPhySrc, IN ULONG readLen, IN PVOID pUserDst)
{
    return MemoryUtils::ReadPhysicalMemory(pPhySrc, readLen, pUserDst);
}

NTSTATUS OperDispatcher::WritePhysicalMemory(IN PBYTE pUserSrc, IN ULONG writeLen, IN PVOID pPhyDst)
{
    return MemoryUtils::WritePhysicalMemory(pUserSrc, writeLen, pPhyDst);
}

NTSTATUS OperDispatcher::GetPhysicalAddress(IN DWORD pid, PVOID virtualAddress, IN PVOID* pPhysicalAddress)
{
    return MemoryUtils::GetPhysicalAddress(pid, virtualAddress, pPhysicalAddress);
}

NTSTATUS OperDispatcher::InjectDllWithNoModuleByAPC(IN DWORD pid, IN LPCWSTR dllPath)
{
    return ProcessUtils::GenerateShellcode(
        pid, dllPath,
        [](PEPROCESS pEprocess, ProcessUtils::Fun_Shellcode pShellcodeAddress, PBYTE pShellCodeParamAddress, SIZE_T totalSize)->NTSTATUS
    {
        // 获取目标进程的一个可以alertable的线程
        PETHREAD pTargetEthread = NULL;
        NTSTATUS ntStatus = ProcessUtils::FindProcessEthread(pEprocess, &pTargetEthread);
        if (!NT_SUCCESS(ntStatus))
        {
            LOG_ERROR("FindProcessThread failed, ntStatus: 0x%x", ntStatus);
            return ntStatus;
        }

        // 创建APC
        ntStatus = ApcUtils::CreateRemoteAPC(pTargetEthread, (PVOID)pShellcodeAddress, (ULONG64)pShellCodeParamAddress);
        if (!NT_SUCCESS(ntStatus))
        {
            LOG_ERROR("CreateRemoteAPC failed");
            ObDereferenceObject(pTargetEthread);
            return ntStatus;
        }

        ObDereferenceObject(pTargetEthread);
        return STATUS_SUCCESS;
    });
}

NTSTATUS OperDispatcher::InjectDllWithNoModuleByEventHook(IN DWORD pid, IN LPCWSTR dllPath)
{
    return ProcessUtils::GenerateShellcode(
        pid,
        dllPath,
        [](PEPROCESS pEprocess, ProcessUtils::Fun_Shellcode pShellcodeAddress, PBYTE pShellCodeParamAddress, SIZE_T totalSize)->NTSTATUS
    {
        //auto target_process_hwnd = utils::get_hwnd_of_process_id(target_process_id); // HWND needed for hook
        //auto nt_dll = LoadLibraryA(xor_a("ntdll.dll"));
        //auto thread_id = GetWindowThreadProcessId(target_process_hwnd, 0); // also needed for hook
        //auto win_event_hook = SetWinEventHook(EVENT_MIN, EVENT_MAX, nt_dll, (WINEVENTPROC)allocated_shellcode, target_process_id, thread_id, WINEVENT_INCONTEXT);
        // NtUserSetWinEventHook(0, 0, NULL, NULL, NULL, 0, 0, 0);
        return STATUS_SUCCESS;
    });
}

NTSTATUS OperDispatcher::ProcessCreateFullDump(IN DWORD pid, IN LPCWSTR dumpPath)
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
    NTSTATUS ntStatus = ProcessUtils::FindProcessEthread(pEprocess, &pTargetEthread);
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("FindProcessThread failed, ntStatus: 0x%x", ntStatus);
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(pEprocess);
        return ntStatus;
    }

    // 获取目标函数地址
    Fun_MiniDumpWriteDump fun_MiniDumpWriteDump = (Fun_MiniDumpWriteDump)MemoryUtils::GetModuleExportAddress("dbghelp.dll", "MiniDumpWriteDump");
    if (NULL == fun_MiniDumpWriteDump)
    {
        LOG_ERROR("GetModuleExportAddress failed");
        ObDereferenceObject(pTargetEthread);
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(pEprocess);
        return STATUS_UNSUCCESSFUL;
    }

    KeUnstackDetachProcess(&apcState);
    
    // 初始化调用信息
    PSET_CONTEXT_CALL_INFORMATION callInfo = (PSET_CONTEXT_CALL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), MEM_TAG);
    if (NULL == callInfo)
    {
        LOG_ERROR("ExAllocatePoolWithTag failed");
        ObDereferenceObject(pTargetEthread);
        ObDereferenceObject(pEprocess);
        return STATUS_UNSUCCESSFUL;
    }

    /*
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
    callInfo->userFunction = (PVOID)fun_MiniDumpWriteDump;
    callInfo->paramCnt = 7;
    callInfo->param[0].asU64 = 0;
    callInfo->param[1].asU64 = pid;
    callInfo->param[2].asU64 = 0;
    callInfo->param[3].asU64 = MiniDumpWithFullMemory;
    callInfo->param[4].asU64 = 0;
    callInfo->param[5].asU64 = 0;
    callInfo->param[6].asU64 = 0;
    callInfo->fun_PreCallKernelRoutine = [](PSET_CONTEXT_CALL_INFORMATION callInf)
    {

    };
    callInfo->fun_PostCallKernelRoutine = [](PSET_CONTEXT_CALL_INFORMATION callInf)
    {

    };

    // 远程调用
    ntStatus = ApcUtils::RemoteCallBySwitchContext(callInfo);
    if (NULL == callInfo)
    {
        LOG_ERROR("ExAllocatePoolWithTag failed");
        ExFreePoolWithTag(callInfo, MEM_TAG);
        ObDereferenceObject(pTargetEthread);
        ObDereferenceObject(pEprocess);
        return STATUS_UNSUCCESSFUL;
    }

    ExFreePoolWithTag(callInfo, MEM_TAG);
    ObDereferenceObject(pTargetEthread);
    ObDereferenceObject(pEprocess);

    return STATUS_SUCCESS;
}
