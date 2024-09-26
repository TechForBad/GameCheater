#include "memoryUtils.h"

PVOID MemoryUtils::GetModuleBaseFor64BitProcess(PEPROCESS proc, PCWSTR moduleName)
{
    PPEB pPeb = PsGetProcessPeb(proc);
    if (!pPeb)
    {
        return NULL;
    }

    KAPC_STATE state;
    KeStackAttachProcess(proc, &state);

    LARGE_INTEGER interval = { 0 };
    for (int i = 0; !pPeb->Ldr && i < 10; i++)
    {
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }
    if (!pPeb->Ldr)
    {
        KeUnstackDetachProcess(&state);
        return NULL;
    }

    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;
    if (!pLdr)
    {
        KeUnstackDetachProcess(&state);
        return NULL;
    }

    PVOID baseAddr = NULL;
    UNICODE_STRING ustrModuleName;
    RtlInitUnicodeString(&ustrModuleName, moduleName);
    for (PLIST_ENTRY pListEntry = pLdr->ModuleListLoadOrder.Flink;
         pListEntry != &pLdr->ModuleListLoadOrder;
         pListEntry = pListEntry->Flink)
    {
        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
        if (0 == RtlCompareUnicodeString(&pEntry->BaseDllName, &ustrModuleName, FALSE))
        {
            baseAddr = pEntry->DllBase;
            break;
        }
    }

    KeUnstackDetachProcess(&state);

    return baseAddr;
}
