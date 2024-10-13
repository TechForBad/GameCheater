#include "processUtils.h"

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

NTSTATUS ProcessUtils::FindProcessEthread(PEPROCESS pProcess, PETHREAD* ppThread)
{
    PSYSTEM_PROCESS_INFO pSystemProcessInfo =
        (PSYSTEM_PROCESS_INFO)MemoryUtils::GetSystemInformation(SystemProcessesAndThreadsInformation);
    if (NULL == pSystemProcessInfo)
    {
        LOG_ERROR("GetSystemInformation failed");
        return STATUS_UNSUCCESSFUL;
    }

    PSYSTEM_PROCESS_INFO pCurProcessInfo =
        FindProcessInformation(pSystemProcessInfo, HandleToULong(PsGetProcessId(pProcess)));
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

OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info)
{
    return OB_PREOP_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS OnPreOpenThread(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info)
{
    return OB_PREOP_SUCCESS;
}
