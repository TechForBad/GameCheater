#include "common.h"

PVOID GetCurrentProcessModule(LPCSTR moduleName, ULONG* moduleSize, BOOL force64)
{
    PEPROCESS Process = IoGetCurrentProcess();

    PPEB32 pPeb32 = (PPEB32)PsGetProcessWow64Process(Process);

    if (pPeb32 && !force64)
    {
        if (NULL == pPeb32->Ldr)
        {
            return NULL;
        }

        for (PLIST_ENTRY32 pListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList.Flink;
             pListEntry != &((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList;
             pListEntry = (PLIST_ENTRY32)pListEntry->Flink)
        {
            PLDR_DATA_TABLE_ENTRY32 pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

            if (StrICmp(moduleName, (PWCH)pEntry->BaseDllName.Buffer, false))
            {
                if (moduleSize)
                {
                    *moduleSize = pEntry->SizeOfImage;
                }

                return (PVOID)pEntry->DllBase;
            }
        }
    }
    else
    {
        PPEB64 pPeb64 = PsGetProcessPeb(Process);
        if (!pPeb64 || !pPeb64->Ldr)
        {
            return NULL;
        }

        for (PLIST_ENTRY pListEntry = (PLIST_ENTRY)((PPEB_LDR_DATA64)(pPeb64->Ldr))->InLoadOrderModuleList.Flink;
             pListEntry != (PLIST_ENTRY) & ((PPEB_LDR_DATA64)(pPeb64->Ldr))->InLoadOrderModuleList;
             pListEntry = pListEntry->Flink)
        {
            PLDR_DATA_TABLE_ENTRY64 pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY64, InLoadOrderLinks);

            if (StrICmp(moduleName, pEntry->BaseDllName.Buffer, false))
            {
                if (moduleSize)
                {
                    *moduleSize = pEntry->SizeOfImage;
                }

                return (PVOID)pEntry->DllBase;
            }
        }
    }

    return NULL;
}

PVOID GetProcAddress(PVOID moduleBase, LPCSTR funcName)
{
    if (NULL == moduleBase)
    {
        LOG_ERROR("Param Error");
        return NULL;
    }

    // parse headers
    PIMAGE_NT_HEADERS pNtHeader = NT_HEADER(moduleBase);
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG64)moduleBase + pNtHeader->OptionalHeader.DataDirectory[0].VirtualAddress);

    // process records
    for (ULONG i = 0; i < pExportDir->NumberOfNames; i++)
    {
        // get ordinal & name
        USHORT ordinal = ((USHORT*)((ULONG64)moduleBase + pExportDir->AddressOfNameOrdinals))[i];
        const char* curExpName = (const char*)moduleBase + ((ULONG*)((ULONG64)moduleBase + pExportDir->AddressOfNames))[i];

        // check export name
        if (StrICmp(funcName, curExpName, true))
        {
            return (PVOID)((ULONG64)moduleBase + ((ULONG*)((ULONG64)moduleBase + pExportDir->AddressOfFunctions))[ordinal]);
        }
    }

    // no export
    return NULL;
}
