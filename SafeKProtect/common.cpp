#include "common.h"

PVOID GetCurrentProcessModule(const char* ModName, ULONG* ModSize, bool force64)
{
    auto Process = IoGetCurrentProcess();

    PPEB32 pPeb32 = (PPEB32)PsGetProcessWow64Process(Process);

    if (pPeb32 && !force64)
    {
        if (!pPeb32->Ldr)
            return nullptr;

        for (PLIST_ENTRY32 pListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList.Flink;
             pListEntry != &((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList;
             pListEntry = (PLIST_ENTRY32)pListEntry->Flink)
        {
            PLDR_DATA_TABLE_ENTRY32 pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

            if (StrICmp(ModName, (PWCH)pEntry->BaseDllName.Buffer, false))
            {
                if (ModSize)
                {
                    *ModSize = pEntry->SizeOfImage;
                }

                return (PVOID)pEntry->DllBase;
            }
        }
    }
    else
    {
        PPEB64 PEB = ImpCall(PsGetProcessPeb, Process);
        if (!PEB || !PEB->Ldr)
            return nullptr;

        for (PLIST_ENTRY pListEntry = (PLIST_ENTRY)((PPEB_LDR_DATA64)(PEB->Ldr))->InLoadOrderModuleList.Flink;
             pListEntry != (PLIST_ENTRY) & ((PPEB_LDR_DATA64)(PEB->Ldr))->InLoadOrderModuleList;
             pListEntry = pListEntry->Flink)
        {
            PLDR_DATA_TABLE_ENTRY64 pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY64, InLoadOrderLinks);

            if (StrICmp(ModName, pEntry->BaseDllName.Buffer, false))
            {
                if (ModSize)
                {
                    *ModSize = pEntry->SizeOfImage;
                }

                return (PVOID)pEntry->DllBase;
            }
        }
    }

    return nullptr;
}
