#include "processUtils.h"

PVOID MemoryUtils::GetModuleBaseFor64BitProcess(PEPROCESS Process, WCHAR* moduleName)
{
    PVOID moduleBase = NULL;
    LARGE_INTEGER time = { 0 };
    time.QuadPart = -100ll * 10 * 1000;

    PREALPEB targetPeb = (PREALPEB)PsGetProcessPeb(Process);

    if (!targetPeb)
        return moduleBase;

    for (int i = 0; !targetPeb->LoaderData && i < 10; i++)
    {
        KeDelayExecutionThread(KernelMode, FALSE, &time);
    }

    if (!targetPeb->LoaderData)
        return moduleBase;

    // Getting the module's image base.
    for (PLIST_ENTRY pListEntry = targetPeb->LoaderData->InLoadOrderModuleList.Flink;
         pListEntry != &targetPeb->LoaderData->InLoadOrderModuleList;
         pListEntry = pListEntry->Flink)
    {

        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (pEntry->FullDllName.Length > 0)
        {
            if (IsIContained(pEntry->FullDllName, moduleName))
            {
                moduleBase = pEntry->DllBase;
                break;
            }
        }
    }

    return moduleBase;
}

PVOID MemoryUtils::GetFunctionAddress(PVOID moduleBase, CHAR* functionName)
{
    PVOID functionAddress = NULL;
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;

    if (!dosHeader)
        return functionAddress;

    // Checking that the image is valid PE file.
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return functionAddress;

    PFULL_IMAGE_NT_HEADERS ntHeaders = (PFULL_IMAGE_NT_HEADERS)((PUCHAR)moduleBase + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        return functionAddress;

    IMAGE_OPTIONAL_HEADER optionalHeader = ntHeaders->OptionalHeader;

    if (optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
        return functionAddress;

    // Iterating the export directory.
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)moduleBase + optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* addresses = (DWORD*)((PUCHAR)moduleBase + exportDirectory->AddressOfFunctions);
    WORD* ordinals = (WORD*)((PUCHAR)moduleBase + exportDirectory->AddressOfNameOrdinals);
    DWORD* names = (DWORD*)((PUCHAR)moduleBase + exportDirectory->AddressOfNames);

    for (DWORD j = 0; j < exportDirectory->NumberOfNames; j++)
    {
        if (_stricmp((char*)((PUCHAR)moduleBase + names[j]), functionName) == 0)
        {
            functionAddress = (PUCHAR)moduleBase + addresses[ordinals[j]];
            break;
        }
    }

    return functionAddress;
}

NTSTATUS MemoryUtils::GetSSDTAddress()
{
    ULONG infoSize = 0;
    PVOID ssdtRelativeLocation = NULL;
    PVOID ntoskrnlBase = NULL;
    PRTL_PROCESS_MODULES info = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    UCHAR pattern[] = "\x4c\x8d\x15\xcc\xcc\xcc\xcc\x4c\x8d\x1d\xcc\xcc\xcc\xcc\xf7";

    // Getting ntoskrnl base first.
    status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &infoSize);

    while (status == STATUS_INFO_LENGTH_MISMATCH)
    {
        if (info)
            ExFreePoolWithTag(info, DRIVER_TAG);
        info = (PRTL_PROCESS_MODULES)AllocateMemory(infoSize);

        if (!info)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        status = ZwQuerySystemInformation(SystemModuleInformation, info, infoSize, &infoSize);
    }

    if (!NT_SUCCESS(status) || !info)
        return status;

    PRTL_PROCESS_MODULE_INFORMATION modules = info->Modules;

    for (ULONG i = 0; i < info->NumberOfModules; i++)
    {
        if (NtCreateFile >= modules[i].ImageBase && NtCreateFile < (PVOID)((PUCHAR)modules[i].ImageBase + modules[i].ImageSize))
        {
            ntoskrnlBase = modules[i].ImageBase;
            break;
        }
    }

    if (!ntoskrnlBase)
    {
        ExFreePoolWithTag(info, DRIVER_TAG);
        return STATUS_NOT_FOUND;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ntoskrnlBase;

    // Finding the SSDT address.
    status = STATUS_NOT_FOUND;

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        ExFreePoolWithTag(info, DRIVER_TAG);
        return STATUS_INVALID_ADDRESS;
    }

    PFULL_IMAGE_NT_HEADERS ntHeaders = (PFULL_IMAGE_NT_HEADERS)((PUCHAR)ntoskrnlBase + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        ExFreePoolWithTag(info, DRIVER_TAG);
        return STATUS_INVALID_ADDRESS;
    }

    PIMAGE_SECTION_HEADER firstSection = (PIMAGE_SECTION_HEADER)(ntHeaders + 1);

    for (PIMAGE_SECTION_HEADER section = firstSection; section < firstSection + ntHeaders->FileHeader.NumberOfSections; section++)
    {
        if (strcmp((const char*)section->Name, ".text") == 0)
        {
            ssdtRelativeLocation = FindPattern(pattern, 0xCC, sizeof(pattern) - 1, (PUCHAR)ntoskrnlBase + section->VirtualAddress, section->Misc.VirtualSize, NULL, NULL);

            if (ssdtRelativeLocation)
            {
                status = STATUS_SUCCESS;
                this->ssdt = (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)((PUCHAR)ssdtRelativeLocation + *(PULONG)((PUCHAR)ssdtRelativeLocation + 3) + 7);
                break;
            }
        }
    }

    ExFreePoolWithTag(info, DRIVER_TAG);
    return status;
}

PVOID MemoryUtils::GetSSDTFunctionAddress(CHAR* functionName)
{
    KAPC_STATE state;
    PEPROCESS CsrssProcess = NULL;
    PVOID functionAddress = NULL;
    ULONG index = 0;
    UCHAR syscall = 0;
    ULONG csrssPid = 0;
    NTSTATUS status = NidhoggProccessUtils->FindPidByName(L"csrss.exe", &csrssPid);

    if (!NT_SUCCESS(status))
        return functionAddress;

    status = PsLookupProcessByProcessId(ULongToHandle(csrssPid), &CsrssProcess);

    if (!NT_SUCCESS(status))
        return functionAddress;

    // Attaching to the process's stack to be able to walk the PEB.
    KeStackAttachProcess(CsrssProcess, &state);
    PVOID ntdllBase = GetModuleBase(CsrssProcess, L"\\Windows\\System32\\ntdll.dll");

    if (!ntdllBase)
    {
        KeUnstackDetachProcess(&state);
        ObDereferenceObject(CsrssProcess);
        return functionAddress;
    }
    PVOID ntdllFunctionAddress = GetFunctionAddress(ntdllBase, functionName);

    if (!ntdllFunctionAddress)
    {
        KeUnstackDetachProcess(&state);
        ObDereferenceObject(CsrssProcess);
        return functionAddress;
    }

    // Searching for the syscall.
    while (((PUCHAR)ntdllFunctionAddress)[index] != RETURN_OPCODE)
    {
        if (((PUCHAR)ntdllFunctionAddress)[index] == MOV_EAX_OPCODE)
        {
            syscall = ((PUCHAR)ntdllFunctionAddress)[index + 1];
        }
        index++;
    }
    KeUnstackDetachProcess(&state);

    if (syscall != 0)
        functionAddress = (PUCHAR)this->ssdt->ServiceTableBase + (((PLONG)this->ssdt->ServiceTableBase)[syscall] >> 4);

    ObDereferenceObject(CsrssProcess);
    return functionAddress;
}
