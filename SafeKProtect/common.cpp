#include "common.h"

PVOID GetCurrentProcessModule(LPCSTR ModName, ULONG* ModSize, BOOL force64)
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
        PPEB64 PEB = PsGetProcessPeb(Process);
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

PVOID GetProcAddress(PVOID ModBase, LPCSTR Name)
{
    if (!ModBase)
    {
        return 0;
    }
    //parse headers
    PIMAGE_NT_HEADERS NT_Head = NT_HEADER(ModBase);
    PIMAGE_EXPORT_DIRECTORY ExportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG64)ModBase + NT_Head->OptionalHeader.DataDirectory[0].VirtualAddress);

    //process records
    for (ULONG i = 0; i < ExportDir->NumberOfNames; i++)
    {
        //get ordinal & name
        USHORT Ordinal = ((USHORT*)((ULONG64)ModBase + ExportDir->AddressOfNameOrdinals))[i];
        const char* ExpName = (const char*)ModBase + ((ULONG*)((ULONG64)ModBase + ExportDir->AddressOfNames))[i];

        //check export name
        if (StrICmp(Name, ExpName, true))
            return (PVOID)((ULONG64)ModBase + ((ULONG*)((ULONG64)ModBase + ExportDir->AddressOfFunctions))[Ordinal]);
    }

    // no export
    return NULL;
}

PVOID UAlloc(ULONG Size, ULONG Protect, BOOL load)
{
    PVOID AllocBase = nullptr; SIZE_T SizeUL = SizeAlign(Size);
#define LOCK_VM_IN_RAM 2
#define LOCK_VM_IN_WORKING_SET 1
    if (!ZwAllocateVirtualMemory(ZwCurrentProcess(), &AllocBase, 0, &SizeUL, MEM_COMMIT, Protect))
    {
        //ZwLockVirtualMemory(ZwCurrentProcess(), &AllocBase, &SizeUL, LOCK_VM_IN_WORKING_SET | LOCK_VM_IN_RAM);
        if (load)
        {
            MemZero(AllocBase, SizeUL);
        }
    }
    return AllocBase;
}

VOID UFree(PVOID Ptr)
{
    SIZE_T SizeUL = 0;
    ZwFreeVirtualMemory(ZwCurrentProcess(), &Ptr, &SizeUL, MEM_RELEASE);
}
