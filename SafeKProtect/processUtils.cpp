#include "processUtils.h"

static ULONG g_processNameOffset = 0;

BOOL ProcessUtils::InitGetProcessNameOffset(PDRIVER_OBJECT pDriverObject)
{
    const char* curProcName = pDriverObject ? "System" : CHEAT_ENGINE_PROCESS_NAME;
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

VOID ProcessUtils::GetProcessName(IN PEPROCESS proc, OUT PCHAR procName)
{
    strcpy(procName, (PCHAR)proc + g_processNameOffset);
    return;
}

PVOID ProcessUtils::GetModuleBaseFor64BitProcess(PEPROCESS proc, PCWSTR moduleName)
{
    PPEB pPeb = PsGetProcessPeb(proc);
    if (NULL == pPeb)
    {
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
        return STATUS_INVALID_PARAMETER;
    }

    PSYSTEM_PROCESS_INFO pProcessInfo = (PSYSTEM_PROCESS_INFO)MemoryUtils::GetSystemInformation(SystemProcessInformation);
    if (NULL == pProcessInfo)
    {
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

OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info)
{
    return OB_PREOP_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS OnPreOpenThread(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info)
{
    return OB_PREOP_SUCCESS;
}
