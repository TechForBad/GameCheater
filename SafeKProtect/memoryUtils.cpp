#include "memoryUtils.h"

static constexpr SIZE_T RETURN_OPCODE = 0xC3;
static constexpr SIZE_T MOV_EAX_OPCODE = 0xB8;

__inline NTSTATUS copy_memory(PEPROCESS src_proc, PEPROCESS target_proc, PVOID src, PVOID dst, SIZE_T size)
{
    SIZE_T bytes;
    return MmCopyVirtualMemory(target_proc, src, src_proc, dst, size, UserMode, &bytes);
}

NTSTATUS KeReadVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
    SIZE_T Bytes;
    if (NT_SUCCESS(MmCopyVirtualMemory(Process, SourceAddress, PsGetCurrentProcess(),
                                       TargetAddress, Size, KernelMode, &Bytes)))
        return STATUS_SUCCESS;
    else
        return STATUS_ACCESS_DENIED;
}

NTSTATUS KeWriteVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
    SIZE_T Bytes;
    if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), SourceAddress, Process,
                                       TargetAddress, Size, KernelMode, &Bytes)))
        return STATUS_SUCCESS;
    else
        return STATUS_ACCESS_DENIED;
}

NTSTATUS MemoryUtils::SafeCopyMemory_R3_to_R0(ULONG_PTR srcAddr, ULONG_PTR dstAddr, ULONG size)
{
    if (!srcAddr || !dstAddr || !size)
    {
        LOG_ERROR("Parameter Error");
        return STATUS_UNSUCCESSFUL;
    }

    ULONG nRemainSize = PAGE_SIZE - (srcAddr & 0xFFF);
    ULONG nCopyedSize = 0;

    while (nCopyedSize < size)
    {
        if (size - nCopyedSize < nRemainSize)
        {
            nRemainSize = size - nCopyedSize;
        }

        // 创建MDL
        PMDL pSrcMdl = IoAllocateMdl((PVOID)(srcAddr & 0xFFFFFFFFFFFFF000), PAGE_SIZE, FALSE, FALSE, NULL);
        if (NULL == pSrcMdl)
        {
            LOG_ERROR("IoAllocateMdl failed");
            return STATUS_UNSUCCESSFUL;
        }

        // 锁定内存页面(UserMode代表应用层)
        __try
        {
            MmProbeAndLockPages(pSrcMdl, UserMode, IoReadAccess);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            LOG_ERROR("Trigger Exception 0x%x", GetExceptionCode());
            IoFreeMdl(pSrcMdl);
            return STATUS_UNSUCCESSFUL;
        }

        // 从MDL中得到映射内存地址
        PVOID pMappedSrc = MmGetSystemAddressForMdlSafe(pSrcMdl, NormalPagePriority);
        if (NULL == pMappedSrc)
        {
            LOG_ERROR("MmGetSystemAddressForMdlSafe failed");
            MmUnlockPages(pSrcMdl);
            IoFreeMdl(pSrcMdl);
            return STATUS_UNSUCCESSFUL;
        }

        // 拷贝内存
        __try
        {
            RtlCopyMemory((PVOID)dstAddr, (PVOID)((ULONG_PTR)pMappedSrc + (srcAddr & 0xFFF)), nRemainSize);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            LOG_ERROR("Trigger Exception 0x%x", GetExceptionCode());
            MmUnlockPages(pSrcMdl);
            IoFreeMdl(pSrcMdl);
            return STATUS_UNSUCCESSFUL;
        }

        MmUnlockPages(pSrcMdl);
        IoFreeMdl(pSrcMdl);

        if (nCopyedSize)
        {
            nRemainSize = PAGE_SIZE;
        }

        nCopyedSize += nRemainSize;
        srcAddr += nRemainSize;
        dstAddr += nRemainSize;
    }

    return STATUS_SUCCESS;
}

NTSTATUS MemoryUtils::SafeCopyMemory_R0_to_R3(PVOID srcAddr, PVOID dstAddr, ULONG size)
{
    PMDL pSrcMdl = NULL;
    PMDL pDstMdl = NULL;
    PVOID pSrcAddress = NULL;
    PVOID pDstAddress = NULL;

    // 分配MDL 源地址
    pSrcMdl = IoAllocateMdl(srcAddr, size, FALSE, FALSE, NULL);
    if (NULL == pSrcMdl)
    {
        LOG_ERROR("IoAllocateMdl failed");
        return STATUS_UNSUCCESSFUL;
    }

    // 该 MDL 指定非分页虚拟内存缓冲区，并对其进行更新以描述基础物理页
    MmBuildMdlForNonPagedPool(pSrcMdl);

    // 获取源地址MDL地址
    pSrcAddress = MmGetSystemAddressForMdlSafe(pSrcMdl, NormalPagePriority);
    if (NULL == pSrcAddress)
    {
        LOG_ERROR("MmGetSystemAddressForMdlSafe failed");
        IoFreeMdl(pSrcMdl);
        return STATUS_UNSUCCESSFUL;
    }

    // 分配MDL 目标地址
    pDstMdl = IoAllocateMdl(dstAddr, size, FALSE, FALSE, NULL);
    if (NULL == pDstMdl)
    {
        LOG_ERROR("IoAllocateMdl failed");
        IoFreeMdl(pSrcMdl);
        return STATUS_UNSUCCESSFUL;
    }

    // 以写入的方式锁定目标MDL
    __try
    {
        MmProbeAndLockPages(pDstMdl, UserMode, IoWriteAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        LOG_ERROR("Trigger Exception 0x%x", GetExceptionCode());
        IoFreeMdl(pDstMdl);
        IoFreeMdl(pSrcMdl);
        return STATUS_UNSUCCESSFUL;
    }

    // 获取目标地址MDL地址
    pDstAddress = MmGetSystemAddressForMdlSafe(pDstMdl, NormalPagePriority);
    if (NULL == pDstAddress)
    {
        LOG_ERROR("MmGetSystemAddressForMdlSafe failed");
        MmUnlockPages(pDstMdl);
        IoFreeMdl(pDstMdl);
        IoFreeMdl(pSrcMdl);
        return STATUS_UNSUCCESSFUL;
    }

    // 拷贝内存
    __try
    {
        RtlCopyMemory(pDstAddress, pSrcAddress, size);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        LOG_ERROR("Trigger Exception 0x%x", GetExceptionCode());
        MmUnlockPages(pDstMdl);
        IoFreeMdl(pDstMdl);
        IoFreeMdl(pSrcMdl);
        return STATUS_UNSUCCESSFUL;
    }

    MmUnlockPages(pDstMdl);
    IoFreeMdl(pDstMdl);
    IoFreeMdl(pSrcMdl);

    return STATUS_SUCCESS;
}

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
        LOG_ERROR("ZwQuerySystemInformation failed");
        return NULL;
    }

    PVOID sysInfo = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, MEM_TAG);
    ntStatus = ZwQuerySystemInformation(sysInfoClass, sysInfo, bytes, &bytes);
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("ZwQuerySystemInformation failed");
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
        LOG_ERROR("GetSystemModuleBase failed");
        return NULL;
    }
    return GetFunctionAddressFromExportTable(moduleBase, exportName);
}

PVOID MemoryUtils::GetFunctionAddressFromExportTable(PVOID moduleBase, LPCSTR functionName)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    if (NULL == pDosHeader)
    {
        LOG_ERROR("pDosHeader is NULL");
        return NULL;
    }

    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        LOG_ERROR("pDosHeader->e_magic != IMAGE_DOS_SIGNATURE");
        return NULL;
    }

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)moduleBase + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        LOG_ERROR("pNtHeaders->Signature != IMAGE_NT_SIGNATURE");
        return NULL;
    }

    IMAGE_OPTIONAL_HEADER pOptionalHeader = pNtHeaders->OptionalHeader;
    if (0 == pOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
    {
        LOG_ERROR("VirtualAddress is NULL");
        return NULL;
    }

    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)moduleBase + pOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* addresses = (DWORD*)((PUCHAR)moduleBase + pExportDirectory->AddressOfFunctions);
    WORD* ordinals = (WORD*)((PUCHAR)moduleBase + pExportDirectory->AddressOfNameOrdinals);
    DWORD* names = (DWORD*)((PUCHAR)moduleBase + pExportDirectory->AddressOfNames);

    PVOID exportAddress = NULL;
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
        LOG_ERROR("PsGetProcessPeb failed");
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
        LOG_ERROR("pLdr is NULL");
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
        LOG_ERROR("pNtHeaders->Signature != IMAGE_NT_SIGNATURE");
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

PSYSTEM_SERVICE_DESCRIPTOR_TABLE MemoryUtils::GetShadowSSDTAddress()
{
    static PSYSTEM_SERVICE_DESCRIPTOR_TABLE g_ShadowSSDT = NULL;
    if (g_ShadowSSDT)
    {
        return g_ShadowSSDT;
    }

    PVOID ntBase = GetNtModuleBase(NULL);
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)ntBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)ntBase + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        LOG_ERROR("pNtHeaders->Signature != IMAGE_NT_SIGNATURE");
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
                g_ShadowSSDT = (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)((PUCHAR)ssdtRVA + *(PULONG)((PUCHAR)ssdtRVA + 10) + 14);
                break;
            }
        }
    }

    return g_ShadowSSDT;
}

PVOID MemoryUtils::GetSSDTFunctionAddress(LPCSTR functionName)
{
    ULONG csrssPid = 0;
    NTSTATUS ntStatus = ProcessUtils::FindPidByName(L"csrss.exe", &csrssPid);
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("FindPidByName failed");
        return NULL;
    }

    PEPROCESS hCsrssProcess = NULL;
    ntStatus = PsLookupProcessByProcessId(ULongToHandle(csrssPid), &hCsrssProcess);
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("PsLookupProcessByProcessId failed");
        return NULL;
    }

    KAPC_STATE apcState;
    KeStackAttachProcess(hCsrssProcess, &apcState);

    PVOID ntdllBase = GetProcessModuleBase(hCsrssProcess, L"ntdll.dll", NULL);
    if (NULL == ntdllBase)
    {
        LOG_ERROR("GetProcessModuleBase failed");
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(hCsrssProcess);
        return NULL;
    }

    // 根据导出表获取导出函数地址，从而获取函数的SSDT索引号
    ULONG functionIndex = GetFunctionIndexFromExportTable(ntdllBase, functionName);
    if (0 == functionIndex)
    {
        LOG_ERROR("GetFunctionIndexFromExportTable failed");
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(hCsrssProcess);
        return NULL;
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(hCsrssProcess);

    PSYSTEM_SERVICE_DESCRIPTOR_TABLE pSSDT = GetSSDTAddress();
    if (NULL == pSSDT)
    {
        LOG_ERROR("pSSDT is NULL");
        return NULL;
    }

    PVOID functionAddress = (PUCHAR)pSSDT->ServiceTableBase + (((PLONG)pSSDT->ServiceTableBase)[functionIndex] >> 4);

    return functionAddress;
}

BOOLEAN MemoryUtils::IsAddressSafe(UINT_PTR startAddress)
{
    // cannonical check. Bits 48 to 63 must match bit 47
    UINT_PTR toppart = (startAddress >> 47);
    if (toppart & 1)
    {
        // toppart must be 0x1ffff
        if (toppart != 0x1ffff)
        {
            return FALSE;
        }
    }
    else
    {
        // toppart must be 0
        if (toppart != 0)
        {
            return FALSE;
        }
    }

    UINT_PTR kernelbase = 0x7fffffffffffffffULL;
    if (startAddress < kernelbase)
    {
        return TRUE;
    }
    else
    {
        PHYSICAL_ADDRESS physical;
        physical.QuadPart = 0;
        physical = MmGetPhysicalAddress((PVOID)startAddress);
        return (physical.QuadPart != 0);
    }
}

static UINT64 g_maxPhysAddress = 0;
static UINT64 getMaxPhysAddress()
{
    if (0 == g_maxPhysAddress)
    {
        int r[4];
        __cpuid(r, 0x80000008);

        // get max physical address
        int physicalbits = r[0] & 0xff;

        g_maxPhysAddress = 0xFFFFFFFFFFFFFFFFULL;
        g_maxPhysAddress = g_maxPhysAddress >> physicalbits;    // if physicalbits==36 then maxPhysAddress=0x000000000fffffff
        g_maxPhysAddress = ~(g_maxPhysAddress << physicalbits); // << 36 = 0xfffffff000000000 .  after inverse : 0x0000000fffffffff		
    }

    return g_maxPhysAddress;
}

NTSTATUS MemoryUtils::ReadPhysicalMemory(IN PBYTE pPhySrc, IN ULONG readLen, IN PVOID pUserDst)
{
    if (((UINT64)pPhySrc > getMaxPhysAddress()) || ((UINT64)pPhySrc + readLen > getMaxPhysAddress()))
    {
        LOG_ERROR("Invalid physical address, phy src start: %p, phy src end: %p", pPhySrc, pPhySrc + readLen);
        return STATUS_UNSUCCESSFUL;
    }

    PMDL outputMdl = IoAllocateMdl(pUserDst, (ULONG)readLen, FALSE, FALSE, NULL);
    __try
    {
        MmProbeAndLockPages(outputMdl, KernelMode, IoWriteAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        LOG_ERROR("Trigger Exception 0x%x", GetExceptionCode());
        IoFreeMdl(outputMdl);
        return STATUS_UNSUCCESSFUL;
    }

    HANDLE hPhysmem = NULL;
    UNICODE_STRING ustrPhysmem;
    OBJECT_ATTRIBUTES objectAttributes;
    RtlInitUnicodeString(&ustrPhysmem, L"\\device\\physicalmemory");
    InitializeObjectAttributes(&objectAttributes, &ustrPhysmem, OBJ_CASE_INSENSITIVE, NULL, NULL);
    NTSTATUS ntStatus = ZwOpenSection(&hPhysmem, SECTION_ALL_ACCESS, &objectAttributes);
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("ZwOpenSection failed, ntStatus: 0x%x", ntStatus);
        MmUnlockPages(outputMdl);
        IoFreeMdl(outputMdl);
        return ntStatus;
    }

    SIZE_T length = 0x2000;     // pinp->bytestoread;   // in case of a overlapping region
    PHYSICAL_ADDRESS viewBase;
    viewBase.QuadPart = (ULONGLONG)(pPhySrc);
    UCHAR* memoryView = NULL;
    ntStatus = ZwMapViewOfSection(
        hPhysmem,               // sectionhandle
        NtCurrentProcess(),     // processhandle (should be -1)
        (PVOID*)&memoryView,    // BaseAddress
        0L,                     // ZeroBits
        length,                 // CommitSize
        &viewBase,              // SectionOffset
        &length,                // ViewSize
        ViewShare,
        0,
        PAGE_READWRITE
    );
    if (!NT_SUCCESS(ntStatus) || (NULL == memoryView))
    {
        LOG_ERROR("ZwMapViewOfSection failed, ntStatus: 0x%x", ntStatus);
        ZwClose(hPhysmem);
        MmUnlockPages(outputMdl);
        IoFreeMdl(outputMdl);
        return STATUS_UNSUCCESSFUL;
    }

    UINT_PTR toread = readLen;
    if (toread > length)
    {
        toread = length;
    }
    if (0 == toread)
    {
        LOG_ERROR("size of mem to read is zero");
        ZwUnmapViewOfSection(NtCurrentProcess(), memoryView);
        ZwClose(hPhysmem);
        MmUnlockPages(outputMdl);
        IoFreeMdl(outputMdl);
        return STATUS_UNSUCCESSFUL;
    }

    UINT_PTR offset = (UINT_PTR)(pPhySrc)-(UINT_PTR)viewBase.QuadPart;
    if (offset + toread > length)
    {
        LOG_ERROR("Too small map");
        ZwUnmapViewOfSection(NtCurrentProcess(), memoryView);
        ZwClose(hPhysmem);
        MmUnlockPages(outputMdl);
        IoFreeMdl(outputMdl);
        return STATUS_UNSUCCESSFUL;
    }

    __try
    {
        RtlCopyMemory(pUserDst, &memoryView[offset], toread);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        LOG_ERROR("Trigger Exception 0x%x", GetExceptionCode());
    }

    ZwUnmapViewOfSection(NtCurrentProcess(), memoryView);
    ZwClose(hPhysmem);
    MmUnlockPages(outputMdl);
    IoFreeMdl(outputMdl);

    return STATUS_SUCCESS;
}

NTSTATUS MemoryUtils::WritePhysicalMemory(IN PBYTE pUserSrc, IN ULONG writeLen, IN PVOID pPhyDst)
{
    HANDLE hPhysmem = NULL;
    UNICODE_STRING ustrPhysmem;
    OBJECT_ATTRIBUTES objectAttributes;
    RtlInitUnicodeString(&ustrPhysmem, L"\\device\\physicalmemory");
    InitializeObjectAttributes(&objectAttributes, &ustrPhysmem, OBJ_CASE_INSENSITIVE, NULL, NULL);
    NTSTATUS ntStatus = ZwOpenSection(&hPhysmem, SECTION_ALL_ACCESS, &objectAttributes);
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("ZwOpenSection failed, ntStatus: 0x%x", ntStatus);
        return ntStatus;
    }

    UCHAR* memoryView = NULL;
    PHYSICAL_ADDRESS viewBase;
    viewBase.QuadPart = (ULONGLONG)pPhyDst;
    SIZE_T length = 0x2000;     // pinp->bytestoread;
    ntStatus = ZwMapViewOfSection(
        hPhysmem,               // sectionhandle
        NtCurrentProcess(),     // processhandle
        (PVOID*)&memoryView,    // BaseAddress
        0L,                     // ZeroBits
        length,                 // CommitSize
        &viewBase,              // SectionOffset
        &length,                // ViewSize
        ViewShare,
        0,
        PAGE_READWRITE
    );
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("ZwMapViewOfSection failed, ntStatus: 0x%x", ntStatus);
        ZwClose(hPhysmem);
        return ntStatus;
    }

    UINT_PTR offset = (UINT_PTR)pPhyDst - (UINT_PTR)viewBase.QuadPart;
    RtlCopyMemory(&memoryView[offset], pUserSrc, writeLen);

    ZwUnmapViewOfSection(NtCurrentProcess(), memoryView);
    ZwClose(hPhysmem);

    return STATUS_SUCCESS;
}

NTSTATUS MemoryUtils::GetPhysicalAddress(IN DWORD pid, PVOID virtualAddress, IN PVOID* pPhysicalAddress)
{
    PEPROCESS pEprocess = NULL;
    NTSTATUS ntStatus = PsLookupProcessByProcessId(ULongToHandle(pid), &pEprocess);
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("PsLookupProcessByProcessId failed, ntStatus: 0x%x", ntStatus);
        return ntStatus;
    }

    KAPC_STATE apc_state;
    RtlZeroMemory(&apc_state, sizeof(apc_state));
    KeStackAttachProcess(pEprocess, &apc_state);

    PHYSICAL_ADDRESS physical;
    physical.QuadPart = 0;
    __try
    {
        physical = MmGetPhysicalAddress(virtualAddress);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        LOG_ERROR("Trigger Exception 0x%x", GetExceptionCode());
        KeUnstackDetachProcess(&apc_state);
        ObDereferenceObject(pEprocess);
        return STATUS_UNSUCCESSFUL;
    }

    KeUnstackDetachProcess(&apc_state);
    ObDereferenceObject(pEprocess);

    RtlCopyMemory(pPhysicalAddress, &physical.QuadPart, 8);

    return STATUS_SUCCESS;
}
