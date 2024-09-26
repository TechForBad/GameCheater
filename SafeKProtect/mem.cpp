#include "mem.h"

namespace mem
{

PVOID GetSystemModuleBase(const char* moduleName, PULONG moduleSize)
{
    ULONG bytes = 0;
    NTSTATUS ntStatus = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
    if (!bytes)
    {
        return NULL;
    }

    PRTL_PROCESS_MODULES processModules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x504D5448);
    ntStatus = ZwQuerySystemInformation(SystemModuleInformation, processModules, bytes, &bytes);
    if (!NT_SUCCESS(ntStatus))
    {
        return NULL;
    }

    PVOID module_base = 0;
    PRTL_PROCESS_MODULE_INFORMATION modules = processModules->Modules;
    for (ULONG i = 0; i < processModules->NumberOfModules; i++)
    {
        if (0 == strcmp((char*)modules[i].FullPathName, moduleName))
        {
            module_base = modules[i].ImageBase;
            *moduleSize = modules[i].ImageSize;
            break;
        }
    }

    if (processModules)
    {
        ExFreePoolWithTag(processModules, 0);
    }
    if (module_base <= 0)
    {
        return NULL;
    }

    return module_base;
}

PVOID GetSystemBaseModuleExport(const char* moduleName, LPCSTR routineName)
{
    ULONG moduleSize = 0;
    PVOID baseModule = mem::GetSystemModuleBase(moduleName, &moduleSize);
    if (!baseModule)
    {
        return NULL;
    }
    return RtlFindExportedRoutineByName(baseModule, routineName);
}

bool WriteMemory(void* address, void* buffer, size_t size)
{
    if (!RtlCopyMemory(address, buffer, size))
    {
        return false;
    }
    else
    {
        return true;
    }
}

bool WriteToReadOnlyMemory(void* address, void* buffer, size_t size)
{
    PMDL pMdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);
    if (!pMdl)
    {
        return false;
    }

    MmProbeAndLockPages(pMdl, KernelMode, IoReadAccess);
    PVOID pMapping = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    MmProtectMdlSystemAddress(pMdl, PAGE_READWRITE);

    WriteMemory(pMapping, buffer, size);

    MmUnmapLockedPages(pMapping, pMdl);
    MmUnlockPages(pMdl);
    IoFreeMdl(pMdl);

    return true;
}

bool Hook(void* destination)
{
    if (!destination)
    {
        return false;
    }

    PVOID* dxgk_routine = reinterpret_cast<PVOID*>(mem::GetSystemBaseModuleExport("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", "NtDxgkGetTrackedWorkloadStatistics"));
    if (!dxgk_routine)
    {
        return false;
    }

    BYTE orignal_shell_code[] = {
        0x90,										// nop
        0x90,										// nop
        0x90,										// nop
        0x48, 0xB8,									// mov rax,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,		// [xxx]
        0x90,										// nop
        0x90,										// nop
        0x48, 0xB8,									// mov rax,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,		// [xxx]
        0xFF, 0xE0,									// jmp rax // d0 for call
        0xCC,										//int3
    };

    BYTE start[]{ 0x48, 0xB8 };
    BYTE end[]{ 0xFF, 0xE0, 0xCC };

    RtlSecureZeroMemory(&orignal_shell_code, sizeof(orignal_shell_code));

    memcpy((PVOID)((ULONG_PTR)orignal_shell_code), &start, sizeof(start));

    uintptr_t test_address = reinterpret_cast<uintptr_t>(destination);

    memcpy((PVOID)((ULONG_PTR)orignal_shell_code + sizeof(start)), &test_address, sizeof(void*));
    memcpy((PVOID)((ULONG_PTR)orignal_shell_code + sizeof(start) + sizeof(void*)), &end, sizeof(end));

    WriteToReadOnlyMemory(dxgk_routine, &orignal_shell_code, sizeof(orignal_shell_code));

    return true;
}



NTSTATUS FindProcessByName(CHAR* processName, PEPROCESS* proc)
{
    PEPROCESS systemProc = PsInitialSystemProcess;
    PEPROCESS curEntry = systemProc;

    CHAR imageName[15];

    do
    {
        RtlCopyMemory((PVOID)(&imageName), (PVOID)((uintptr_t)curEntry + 0x5a8) /*EPROCESS->ImageFileName*/, sizeof(imageName));

        if (strstr(imageName, processName))
        {
            DWORD active_threads;
            RtlCopyMemory((PVOID)&active_threads, (PVOID)((uintptr_t)curEntry + 0x5f0) /*EPROCESS->ActiveThreads*/, sizeof(active_threads));
            if (active_threads)
            {
                *proc = curEntry;
                return STATUS_SUCCESS;
            }
        }

        PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curEntry)+0x448) /*EPROCESS->ActiveProcessLinks*/;
        curEntry = (PEPROCESS)((uintptr_t)list->Flink - 0x448);

    } while (curEntry != systemProc);

    return STATUS_NOT_FOUND;
}

}
