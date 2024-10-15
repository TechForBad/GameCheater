#include "processUtils.h"

#include "processdef.h"

static ULONG g_processNameOffset = 0;

BOOL ProcessUtils::Init(PDRIVER_OBJECT pDriverObject)
{
    const char* curProcName = pDriverObject ? "System" : PROCESS_NAME_IN_EPROCESS_CHEAT_ENGINE;
    size_t curProcNameLen = strlen(curProcName);

    PEPROCESS curProc = PsGetCurrentProcess();
    for (int i = 0; i < 3 * PAGE_SIZE; ++i)
    {
        if (0 == _strnicmp(curProcName, (PCHAR)curProc + i, curProcNameLen))
        {
            g_processNameOffset = i;
            break;
        }
    }

    return (g_processNameOffset != 0);
}

VOID ProcessUtils::GetProcessName(PEPROCESS proc, PCHAR procName)
{
    strcpy(procName, (PCHAR)proc + g_processNameOffset);
    return;
}

PVOID ProcessUtils::GetModuleBaseFor64BitProcess(PEPROCESS proc, PCWSTR moduleName)
{
    PPEB pPeb = PsGetProcessPeb(proc);
    if (NULL == pPeb)
    {
        LOG_ERROR("PsGetProcessPeb failed");
        return NULL;
    }

    KAPC_STATE state;
    KeStackAttachProcess(proc, &state);

    LARGE_INTEGER interval = { 0 };
    interval.QuadPart = -100ll * 10 * 1000;
    for (int i = 0; !pPeb->Ldr && i < 10; ++i)
    {
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }

    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;
    if (NULL == pLdr)
    {
        LOG_ERROR("pLdr is NULL");
        KeUnstackDetachProcess(&state);
        ObDereferenceObject(proc);
        return NULL;
    }

    PVOID dllBaseAddr = NULL;
    UNICODE_STRING ustrModuleName;
    RtlInitUnicodeString(&ustrModuleName, moduleName);
    for (PLIST_ENTRY pListEntry = pLdr->ModuleListLoadOrder.Flink;
         pListEntry != &pLdr->ModuleListLoadOrder;
         pListEntry = pListEntry->Flink)
    {
        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
        if (0 == RtlCompareUnicodeString(&pEntry->BaseDllName, &ustrModuleName, FALSE))
        {
            dllBaseAddr = pEntry->DllBase;
            break;
        }
    }

    KeUnstackDetachProcess(&state);
    ObDereferenceObject(proc);

    return dllBaseAddr;
}

NTSTATUS ProcessUtils::FindPidByName(LPCWSTR processName, PULONG pid)
{
    if ((NULL == processName) || (NULL == pid))
    {
        LOG_ERROR("Param error");
        return STATUS_INVALID_PARAMETER;
    }

    PSYSTEM_PROCESS_INFO pProcessInfo = (PSYSTEM_PROCESS_INFO)MemoryUtils::GetSystemInformation(SystemProcessesAndThreadsInformation);
    if (NULL == pProcessInfo)
    {
        LOG_ERROR("GetSystemInformation failed");
        return STATUS_UNSUCCESSFUL;
    }

    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    PSYSTEM_PROCESS_INFO pCurProcessInfo = pProcessInfo;
    while (pCurProcessInfo->NextEntryOffset)
    {
        if (pCurProcessInfo->ImageName.Buffer && pCurProcessInfo->ImageName.Length > 0)
        {
            if (0 == _wcsicmp(pCurProcessInfo->ImageName.Buffer, processName))
            {
                ntStatus = STATUS_SUCCESS;
                *pid = HandleToULong(pCurProcessInfo->UniqueProcessId);
                break;
            }
        }
        pCurProcessInfo = (PSYSTEM_PROCESS_INFO)((PUCHAR)pCurProcessInfo + pCurProcessInfo->NextEntryOffset);
    }

    if (pProcessInfo)
    {
        ExFreePoolWithTag(pProcessInfo, MEM_TAG);
    }

    return ntStatus;
}

PSYSTEM_PROCESS_INFO ProcessUtils::FindProcessInformation(PSYSTEM_PROCESS_INFO pSystemProcessInfo, ULONG pid)
{
    for (;;)
    {
        if (pSystemProcessInfo->UniqueProcessId == ULongToHandle(pid))
        {
            return pSystemProcessInfo;
        }
        else if (pSystemProcessInfo->NextEntryOffset)
        {
            pSystemProcessInfo = (PSYSTEM_PROCESS_INFO)((PUCHAR)pSystemProcessInfo + pSystemProcessInfo->NextEntryOffset);
        }
        else
        {
            break;
        }
    }
    return NULL;
}

NTSTATUS ProcessUtils::SuspendTargetThread(DWORD tid)
{
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS ProcessUtils::ResumeTargetThread(DWORD tid)
{
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS ProcessUtils::SuspendTargetProcess(DWORD pid)
{
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS ProcessUtils::ResumeTargetProcess(DWORD pid)
{
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS ProcessUtils::FindProcessEthread(PEPROCESS pEprocess, PETHREAD* ppThread)
{
    PSYSTEM_PROCESS_INFO pSystemProcessInfo =
        (PSYSTEM_PROCESS_INFO)MemoryUtils::GetSystemInformation(SystemProcessesAndThreadsInformation);
    if (NULL == pSystemProcessInfo)
    {
        LOG_ERROR("GetSystemInformation failed");
        return STATUS_UNSUCCESSFUL;
    }

    PSYSTEM_PROCESS_INFO pCurProcessInfo =
        FindProcessInformation(pSystemProcessInfo, HandleToULong(PsGetProcessId(pEprocess)));
    if (NULL == pCurProcessInfo)
    {
        LOG_ERROR("FindProcessInformation failed");
        ExFreePoolWithTag(pSystemProcessInfo, MEM_TAG);
        return STATUS_UNSUCCESSFUL;
    }

    PETHREAD pTargetEthread = NULL;
    for (ULONG i = 0; i < pCurProcessInfo->NumberOfThreads; ++i)
    {
        HANDLE tid = pCurProcessInfo->Threads[i].ClientId.UniqueThread;

        if (PsGetCurrentThreadId() == tid)
        {
            continue;
        }

        PETHREAD pEthread = NULL;
        NTSTATUS ntStatus = PsLookupThreadByThreadId(tid, &pEthread);
        if (!NT_SUCCESS(ntStatus))
        {
            LOG_ERROR("PsLookupThreadByThreadId failed, ntStatus: 0x%x", ntStatus);
            continue;
        }

        if (SkipThread(pEthread))
        {
            ObDereferenceObject(pEthread);
            continue;
        }

        pTargetEthread = pEthread;
        break;
    }

    ExFreePoolWithTag(pSystemProcessInfo, MEM_TAG);

    if (NULL == pTargetEthread)
    {
        LOG_ERROR("Can not find target thread");
        return STATUS_NOT_FOUND;
    }

    *ppThread = pTargetEthread;

    return STATUS_SUCCESS;
}

BOOL ProcessUtils::SkipThread(PETHREAD pThread)
{
    if (PsIsThreadTerminating(pThread))
    {
        LOG_ERROR("Skipping thread with terminating");
        return TRUE;
    }

    ULONG guiThread = *(PULONG64)((PUCHAR)pThread + GUI_THREAD_FLAG_OFFSET) & GUI_THREAD_FLAG_BIT;
    ULONG alertableThread = *(PULONG64)((PUCHAR)pThread + ALERTABLE_THREAD_FLAG_OFFSET) & ALERTABLE_THREAD_FLAG_BIT;

    if (guiThread != 0 ||
        alertableThread == 0 ||
        *(PULONG64)((PUCHAR)pThread + THREAD_KERNEL_STACK_OFFSET) == 0 ||
        *(PULONG64)((PUCHAR)pThread + THREAD_CONTEXT_STACK_POINTER_OFFSET) == 0)
    {
        LOG_ERROR("Skipping thread with some error flag");
        return TRUE;
    }

    PUCHAR pTeb64 = (PUCHAR)PsGetThreadTeb(pThread);

    // Skip GUI treads.
    if (*(PULONG64)(pTeb64 + 0x78) != 0)
    {
        // Win32ThreadInfo
        LOG_ERROR("Skipping GUI thread");
        return TRUE;
    }

    // Skip threads with no ActivationContext
    if (*(PULONG64)(pTeb64 + 0x2C8) == 0)
    {
        // ActivationContextStackPointer
        LOG_ERROR("Skipping thread with no ActivationContext");
        return TRUE;
    }

    // Skip threads with no TLS pointer
    if (*(PULONG64)(pTeb64 + 0x58) == 0)
    {
        // ThreadLocalStoragePointer
        LOG_ERROR("Skipping thread with no TLS pointer");
        return TRUE;
    }

    return FALSE;
}

NTSTATUS ProcessUtils::FindAlertableThread(PEPROCESS pEprocess, PETHREAD* pAlertableEthread)
{
    PSYSTEM_PROCESS_INFO pSystemProcessInfo =
        (PSYSTEM_PROCESS_INFO)MemoryUtils::GetSystemInformation(SystemProcessesAndThreadsInformation);
    if (NULL == pSystemProcessInfo)
    {
        LOG_ERROR("GetSystemInformation failed");
        return STATUS_UNSUCCESSFUL;
    }

    PSYSTEM_PROCESS_INFO info =
        ProcessUtils::FindProcessInformation(pSystemProcessInfo, HandleToULong(PsGetProcessId(pEprocess)));
    if (NULL == info)
    {
        LOG_ERROR("FindProcessInformation failed");
        ExFreePoolWithTag(pSystemProcessInfo, MEM_TAG);
        return STATUS_UNSUCCESSFUL;
    }

    PETHREAD pTargetEthread = NULL;
    for (ULONG i = 0; i < info->NumberOfThreads; ++i)
    {
        HANDLE tid = info->Threads[i].ClientId.UniqueThread;

        if (PsGetCurrentThreadId() == tid)
        {
            continue;
        }

        PETHREAD pCurEthread = NULL;
        if (!NT_SUCCESS(PsLookupThreadByThreadId(tid, &pCurEthread)))
        {
            continue;
        }

        if (PsIsThreadTerminating(pCurEthread))
        {
            ObDereferenceObject(pCurEthread);
            continue;
        }

        ULONG guiThread = *(PULONG64)((PUCHAR)pCurEthread + GUI_THREAD_FLAG_OFFSET) & GUI_THREAD_FLAG_BIT;
        ULONG alertableThread = *(PULONG64)((PUCHAR)pCurEthread + ALERTABLE_THREAD_FLAG_OFFSET) & ALERTABLE_THREAD_FLAG_BIT;

        if (guiThread != 0 ||
            alertableThread == 0 ||
            *(PULONG64)((PUCHAR)pCurEthread + THREAD_KERNEL_STACK_OFFSET) == 0 ||
            *(PULONG64)((PUCHAR)pCurEthread + THREAD_CONTEXT_STACK_POINTER_OFFSET) == 0)
        {
            ObDereferenceObject(pCurEthread);
            continue;
        }

        pTargetEthread = pCurEthread;
        break;
    }

    ExFreePoolWithTag(pSystemProcessInfo, MEM_TAG);
    
    if (NULL == pTargetEthread)
    {
        LOG_ERROR("Can not find target thread");
        return STATUS_NOT_FOUND;
    }

    *pAlertableEthread = pTargetEthread;

    return STATUS_SUCCESS;
}

NTSTATUS ProcessUtils::GenerateShellcode(DWORD pid, LPCWSTR dllPath, InjectShellcodeCallback callback)
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

    // 调用注入shellcode回调
    ntStatus = callback(pEprocess, (Fun_Shellcode)pShellcodeAddress, pShellCodeParamAddress, totalSize);
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("inject shellcode callback failed, ntStatus: 0x%x", ntStatus);
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(pEprocess);
        return ntStatus;
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(pEprocess);
    return STATUS_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info)
{
    return OB_PREOP_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS OnPreOpenThread(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info)
{
    return OB_PREOP_SUCCESS;
}
