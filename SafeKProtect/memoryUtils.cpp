#include "memoryUtils.h"

constexpr SIZE_T RETURN_OPCODE = 0xC3;
constexpr SIZE_T MOV_EAX_OPCODE = 0xB8;

BOOLEAN MemoryUtils::DataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
    for (; *szMask; ++szMask, ++pData, ++bMask)
    {
        if (*szMask == 'x' && *pData != *bMask)
        {
            return 0;
        }
    }
    return (*szMask) == 0;
}

BYTE* MemoryUtils::FindPattern(BYTE* pAddress, UINT64 dwLen, const BYTE* bMask, char* szMask)
{
    for (UINT64 i = 0; i < dwLen; i++)
    {
        if (DataCompare(pAddress + i, bMask, szMask))
        {
            return pAddress + i;
        }
    }
    return NULL;
}

PVOID MemoryUtils::GetSystemInformation(SYSTEM_INFORMATION_CLASS sysInfoClass)
{
    ULONG bytes = 0;
    NTSTATUS ntStatus = ZwQuerySystemInformation(sysInfoClass, 0, bytes, &bytes);
    if (!bytes)
    {
        return NULL;
    }

    PVOID sysInfo = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, MEM_TAG);
    ntStatus = ZwQuerySystemInformation(sysInfoClass, sysInfo, bytes, &bytes);
    if (!NT_SUCCESS(ntStatus))
    {
        return NULL;
    }

    return sysInfo;
}

PVOID MemoryUtils::GetSystemModuleBase(LPCSTR moduleName, PULONG moduleSize)
{
    PRTL_PROCESS_MODULES processModules = (PRTL_PROCESS_MODULES)GetSystemInformation(SystemModuleInformation);

    PVOID moduleBase = NULL;
    PRTL_PROCESS_MODULE_INFORMATION modules = processModules->Modules;
    for (ULONG i = 0; i < processModules->NumberOfModules; ++i)
    {
        if (0 == strcmp((LPCSTR)modules[i].FullPathName, moduleName))
        {
            moduleBase = modules[i].ImageBase;
            if (moduleSize)
            {
                *moduleSize = modules[i].ImageSize;
            }
            break;
        }
    }

    if (processModules)
    {
        ExFreePoolWithTag(processModules, MEM_TAG);
    }

    return moduleBase;
}

PVOID MemoryUtils::GetModuleExportAddress(LPCSTR moduleName, LPCSTR exportName)
{
    ULONG moduleSize = 0;
    PVOID moduleBase = GetSystemModuleBase(moduleName, &moduleSize);
    if (NULL == moduleBase)
    {
        return NULL;
    }
    return GetFunctionAddressFromExportTable(moduleBase, exportName);
}

PVOID MemoryUtils::GetFunctionAddressFromExportTable(PVOID moduleBase, LPCSTR functionName)
{
    PVOID exportAddress = NULL;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    if (!pDosHeader)
    {
        return exportAddress;
    }

    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return exportAddress;
    }

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)moduleBase + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        return exportAddress;
    }

    IMAGE_OPTIONAL_HEADER pOptionalHeader = pNtHeaders->OptionalHeader;
    if (0 == pOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
    {
        return exportAddress;
    }

    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)moduleBase + pOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* addresses = (DWORD*)((PUCHAR)moduleBase + pExportDirectory->AddressOfFunctions);
    WORD* ordinals = (WORD*)((PUCHAR)moduleBase + pExportDirectory->AddressOfNameOrdinals);
    DWORD* names = (DWORD*)((PUCHAR)moduleBase + pExportDirectory->AddressOfNames);

    for (ULONG j = 0; j < pExportDirectory->NumberOfNames; ++j)
    {
        if (0 == _stricmp((char*)((PUCHAR)moduleBase + names[j]), functionName))
        {
            exportAddress = (PUCHAR)moduleBase + addresses[ordinals[j]];
            break;
        }
    }

    return exportAddress;
}

ULONG MemoryUtils::GetFunctionIndexFromExportTable(PVOID moduleBase, LPCSTR functionName)
{
    ULONG ulFunctionIndex = 0;
    // Dos Header
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    // NT Header
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + pDosHeader->e_lfanew);
    // Export Table
    PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
    // 有名称的导出函数个数
    ULONG ulNumberOfNames = pExportTable->NumberOfNames;
    // 导出函数名称地址表
    PULONG lpNameArray = (PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfNames);
    PCHAR lpName = NULL;
    // 开始遍历导出表
    for (ULONG i = 0; i < ulNumberOfNames; ++i)
    {
        lpName = (PCHAR)((PUCHAR)pDosHeader + lpNameArray[i]);
        // 判断是否查找的函数
        if (0 == _strnicmp(functionName, lpName, strlen(functionName)))
        {
            // 获取导出函数地址
            USHORT uHint = *(USHORT*)((PUCHAR)pDosHeader + pExportTable->AddressOfNameOrdinals + 2 * i);
            ULONG ulFuncAddr = *(PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfFunctions + 4 * uHint);
            PVOID lpFuncAddr = (PVOID)((PUCHAR)pDosHeader + ulFuncAddr);
            // 获取 SSDT 函数 Index
#ifdef _WIN64 // 64bit
            ulFunctionIndex = *(ULONG*)((PUCHAR)lpFuncAddr + 4);
#else		  // 32bits
            ulFunctionIndex = *(ULONG*)((PUCHAR)lpFuncAddr + 1);
#endif
            break;
        }
    }

    return ulFunctionIndex;
}

PVOID MemoryUtils::GetProcessModuleBase(PEPROCESS proc, PCWSTR moduleName, PULONG moduleSize)
{
    PPEB pPeb = PsGetProcessPeb(proc);
    if (NULL == pPeb)
    {
        return NULL;
    }

    LARGE_INTEGER intervalTime = { 0 };
    intervalTime.QuadPart = -100ll * 10 * 1000;
    for (ULONG i = 0; !pPeb->Ldr && i < 10; ++i)
    {
        KeDelayExecutionThread(KernelMode, FALSE, &intervalTime);
    }

    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;
    if (NULL == pLdr)
    {
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
            if (moduleSize)
            {
                *moduleSize = pEntry->SizeOfImage;
            }
            break;
        }
    }

    return dllBaseAddr;
}

PVOID MemoryUtils::GetNtModuleBase(PULONG ntSize)
{
    static PVOID g_ntBase = NULL;
    static ULONG g_ntSize = 0;
    if (g_ntBase && g_ntSize)
    {
        if (ntSize)
        {
            *ntSize = g_ntSize;
        }
        return g_ntBase;
    }

    PVOID ntBase = NULL;
    PRTL_PROCESS_MODULES processModules = (PRTL_PROCESS_MODULES)GetSystemInformation(SystemModuleInformation);
    if (NULL == processModules)
    {
        return NULL;
    }

    PRTL_PROCESS_MODULE_INFORMATION modules = processModules->Modules;
    for (ULONG i = 0; i < processModules->NumberOfModules; ++i)
    {
        if ((NtCreateFile >= modules[i].ImageBase) && (NtCreateFile < (PVOID)((PUCHAR)modules[i].ImageBase + modules[i].ImageSize)))
        {
            g_ntBase = modules[i].ImageBase;
            g_ntSize = modules[i].ImageSize;
            break;
        }
    }

    if (processModules)
    {
        ExFreePoolWithTag(processModules, MEM_TAG);
    }

    if (ntSize)
    {
        *ntSize = g_ntSize;
    }
    return g_ntBase;
}

PSYSTEM_SERVICE_DESCRIPTOR_TABLE MemoryUtils::GetSSDTAddress()
{
    static PSYSTEM_SERVICE_DESCRIPTOR_TABLE g_SSDT = NULL;
    if (g_SSDT)
    {
        return g_SSDT;
    }

    PVOID ntBase = GetNtModuleBase(NULL);
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)ntBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)ntBase + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        return NULL;
    }

    PIMAGE_SECTION_HEADER pFirstSectionHeader = (PIMAGE_SECTION_HEADER)((PUCHAR)pNtHeaders + sizeof(IMAGE_NT_HEADERS));
    for (PIMAGE_SECTION_HEADER pCurSectionHeader = pFirstSectionHeader;
         pCurSectionHeader < pFirstSectionHeader + pNtHeaders->FileHeader.NumberOfSections;
         ++pCurSectionHeader)
    {
        if (0 == strcmp((const char*)pCurSectionHeader->Name, ".text"))
        {
            PVOID ssdtRVA = FindPattern(
                (PUCHAR)ntBase + pCurSectionHeader->VirtualAddress,
                pCurSectionHeader->Misc.VirtualSize,
                (BYTE*)"\x4c\x8d\x15\xcc\xcc\xcc\xcc\x4c\x8d\x1d\xcc\xcc\xcc\xcc\xf7",
                "xxx????xxx????x");
            if (ssdtRVA)
            {
                g_SSDT = (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)((PUCHAR)ssdtRVA + *(PULONG)((PUCHAR)ssdtRVA + 3) + 7);
                break;
            }
        }
    }

    return g_SSDT;
}

PVOID MemoryUtils::GetSSDTFunctionAddress(LPCSTR functionName)
{
    ULONG csrssPid = 0;
    NTSTATUS ntStatus = ProcessUtils::FindPidByName(L"csrss.exe", &csrssPid);
    if (!NT_SUCCESS(ntStatus))
    {
        return NULL;
    }

    PEPROCESS hCsrssProcess = NULL;
    ntStatus = PsLookupProcessByProcessId(ULongToHandle(csrssPid), &hCsrssProcess);
    if (!NT_SUCCESS(ntStatus))
    {
        return NULL;
    }

    KAPC_STATE apcState;
    KeStackAttachProcess(hCsrssProcess, &apcState);

    PVOID ntdllBase = GetProcessModuleBase(hCsrssProcess, L"ntdll.dll", NULL);
    if (NULL == ntdllBase)
    {
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(hCsrssProcess);
        return NULL;
    }

    // 根据导出表获取导出函数地址，从而获取函数的SSDT索引号
    ULONG functionIndex = GetFunctionIndexFromExportTable(ntdllBase, functionName);
    if (0 == functionIndex)
    {
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(hCsrssProcess);
        return NULL;
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(hCsrssProcess);

    PSYSTEM_SERVICE_DESCRIPTOR_TABLE pSSDT = GetSSDTAddress();
    if (NULL == pSSDT)
    {
        return NULL;
    }

    PVOID functionAddress = (PUCHAR)pSSDT->ServiceTableBase + (((PLONG)pSSDT->ServiceTableBase)[functionIndex] >> 4);

    return functionAddress;
}
