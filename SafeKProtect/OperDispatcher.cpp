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
        KAPC_ENVIRONMENT::OriginalApcEnvironment,               // Environment
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

NTSTATUS OperDispatcher::CreateRemoteAPC(IN DWORD tid, IN PVOID addrToExe)
{
    PETHREAD pEthread = NULL;
    NTSTATUS ntStatus = PsLookupThreadByThreadId(ULongToHandle(tid), &pEthread);
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("PsLookupThreadByThreadId failed, ntStatus: 0x%x", ntStatus);
        return ntStatus;
    }

    PKAPC kernelModeApc = (PKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), MEM_TAG);
    if (NULL == kernelModeApc)
    {
        LOG_ERROR("ExAllocatePoolWithTag failed");
        ObDereferenceObject(pEthread);
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
        NULL                                            // NormalContext
    );

    KeInsertQueueApc(
        kernelModeApc,                                  // Apc
        addrToExe,                                      // SystemArgument1
        NULL,                                           // SystemArgument2
        0                                               // Increment
    );

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
    PEPROCESS pEprocess = NULL;
    NTSTATUS ntStatus = PsLookupProcessByProcessId(ULongToHandle(pid), &pEprocess);
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("PsLookupProcessByProcessId failed, ntStatus: 0x%x", ntStatus);
        return ntStatus;
    }

    KAPC_STATE apcState;
    KeStackAttachProcess(pEprocess, &apcState);

    // 文件buffer
    PVOID pFileBuffer = NULL;
    DWORD dwFileSize = 0;
    UNICODE_STRING ustrDllPath;
    RtlInitUnicodeString(&ustrDllPath, dllPath);
    ntStatus = FileUtils::LoadFile(&ustrDllPath, &pFileBuffer, &dwFileSize);
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("LoadFile failed, ntStatus: 0x%x", ntStatus);
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(pEprocess);
        return ntStatus;
    }

    // shellcode
    ULONG shellcodeSize = 0;
    PVOID pShellcodeBuffer = GetShellCodeBuffer(shellcodeSize);
    if (NULL == pShellcodeBuffer || 0 == shellcodeSize)
    {
        LOG_ERROR("GetShellCodeBuffer failed");
        ExFreePoolWithTag(pFileBuffer, MEM_TAG);
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(pEprocess);
        return STATUS_UNSUCCESSFUL;
    }

    // 参数
    INJECTPARAM injectParam;
    RtlZeroMemory(&injectParam, sizeof(INJECTPARAM));
    injectParam.dwDataLength = dwFileSize;
    ULONG moduleSize = 0;
    PVOID pModuleBase = MemoryUtils::GetProcessModuleBase(pEprocess, L"ntdll.dll", &moduleSize);
    if (NULL == pModuleBase || 0 == moduleSize)
    {
        LOG_ERROR("GetProcessModuleBase failed");
        ExFreePoolWithTag(pFileBuffer, MEM_TAG);
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(pEprocess);
        return STATUS_UNSUCCESSFUL;
    }
    injectParam.fun_LdrGetProcedureAddress = (FUN_LDRGETPROCEDUREADDRESS)MemoryUtils::GetFunctionAddressFromExportTable(pModuleBase, "LdrGetProcedureAddress");
    injectParam.fun_NtAllocateVirtualMemory = (FUN_NTALLOCATEVIRTUALMEMORY)MemoryUtils::GetFunctionAddressFromExportTable(pModuleBase, "NtAllocateVirtualMemory");
    injectParam.fun_LdrLoadDll = (FUN_LDRLOADDLL)MemoryUtils::GetFunctionAddressFromExportTable(pModuleBase, "LdrLoadDll");
    injectParam.fun_RtlInitAnsiString = (FUN_RTLINITANSISTRING)MemoryUtils::GetFunctionAddressFromExportTable(pModuleBase, "RtlInitAnsiString");
    injectParam.fun_RtlAnsiStringToUnicodeString = (FUN_RTLANSISTRINGTOUNICODESTRING)MemoryUtils::GetFunctionAddressFromExportTable(pModuleBase, "RtlAnsiStringToUnicodeString");
    injectParam.fun_RtlFreeUnicodeString = (RTLFREEUNICODESTRING)MemoryUtils::GetFunctionAddressFromExportTable(pModuleBase, "RtlFreeUnicodeString");
    if (NULL == injectParam.fun_LdrGetProcedureAddress ||
        NULL == injectParam.fun_NtAllocateVirtualMemory ||
        NULL == injectParam.fun_LdrLoadDll ||
        NULL == injectParam.fun_RtlInitAnsiString ||
        NULL == injectParam.fun_RtlAnsiStringToUnicodeString ||
        NULL == injectParam.fun_RtlFreeUnicodeString)
    {
        LOG_ERROR("GetFunctionAddressFromExportTable failed");
        ExFreePoolWithTag(pFileBuffer, MEM_TAG);
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(pEprocess);
        return STATUS_UNSUCCESSFUL;
    }

    // 申请内存，把Shellcode和DLL数据，和参数复制到目标进程
    // 安全起见，大小多加0x100
    SIZE_T totalSize = dwFileSize + 0x100 + shellcodeSize + sizeof(injectParam);
    PBYTE pStartAddress = NULL;
    ntStatus = ZwAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&pStartAddress, 0, &totalSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("ZwAllocateVirtualMemory failed, ntStatus: 0x%x", ntStatus);
        ExFreePoolWithTag(pFileBuffer, MEM_TAG);
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(pEprocess);
        return ntStatus;
    }
    injectParam.lpFileData = pStartAddress;

    // 写入dll文件
    memcpy(pStartAddress, pFileBuffer, dwFileSize);
    // 写入shellcode
    PBYTE pShellcodeAddress = pStartAddress + dwFileSize + 0x100;
    memcpy(pShellcodeAddress, pShellcodeBuffer, shellcodeSize);
    // 写入参数
    PBYTE pShellCodeParamAddress = pStartAddress + dwFileSize + 0x100 + shellcodeSize;
    memcpy(pShellCodeParamAddress, &injectParam, sizeof(injectParam));

    LOG_INFO("StartAddress: 0x%llx, ShellCodeAddress: 0x%llx, ShellCodeParamAddress: 0x%llx",
              pStartAddress, pShellcodeAddress, pShellCodeParamAddress);

    ExFreePoolWithTag(pFileBuffer, MEM_TAG);
    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(pEprocess);

    // 获取目标进程的一个线程
    HANDLE targetTid = 0;
    PSYSTEM_PROCESS_INFO pProcessInfo = (PSYSTEM_PROCESS_INFO)MemoryUtils::GetSystemInformation(SystemProcessesAndThreadsInformation);
    if (NULL == pProcessInfo)
    {
        LOG_ERROR("GetSystemInformation failed");
        return STATUS_UNSUCCESSFUL;
    }
    PSYSTEM_PROCESS_INFO pCurProcessInfo = pProcessInfo;
    while (pCurProcessInfo->NextEntryOffset)
    {
        if (pCurProcessInfo->UniqueProcessId == ULongToHandle(pid))
        {
            if (0 == pCurProcessInfo->NumberOfThreads)
            {
                break;
            }

            targetTid = pCurProcessInfo->Threads[0].ClientId.UniqueThread;
            break;
        }
        pCurProcessInfo = (PSYSTEM_PROCESS_INFO)((PUCHAR)pCurProcessInfo + pCurProcessInfo->NextEntryOffset);
    }
    ExFreePoolWithTag(pProcessInfo, MEM_TAG);
    if (NULL == targetTid)
    {
        LOG_ERROR("GetSystemInformation failed");
        return STATUS_UNSUCCESSFUL;
    }

    PETHREAD pTargetEthread = NULL;
    ntStatus = PsLookupThreadByThreadId(targetTid, &pTargetEthread);
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("PsLookupThreadByThreadId failed, ntStatus: 0x%x", ntStatus);
        return ntStatus;
    }

    // 分配APC
    PKAPC kernelModeApc = (PKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), MEM_TAG);
    if (NULL == kernelModeApc)
    {
        LOG_ERROR("ExAllocatePoolWithTag failed");
        ObDereferenceObject(pTargetEthread);
        return STATUS_UNSUCCESSFUL;
    }
    
    // 初始化APC
    KeInitializeApc(
        kernelModeApc,                                  // Apc
        pTargetEthread,                                 // Thread
        KAPC_ENVIRONMENT::OriginalApcEnvironment,       // Environment
        KernelKernelRoutine,                            // KernelRoutine
        NULL,                                           // RundownRoutine
        KernelNormalRoutine,                            // NormalRoutine
        KernelMode,                                     // ApcMode
        pShellCodeParamAddress                          // NormalContext
    );

    // 插入APC
    KeInsertQueueApc(
        kernelModeApc,                                  // Apc
        pShellcodeAddress,                              // SystemArgument1
        pShellcodeAddress,                              // SystemArgument2
        0                                               // Increment
    );

    ObDereferenceObject(pTargetEthread);

    return STATUS_SUCCESS;
}
