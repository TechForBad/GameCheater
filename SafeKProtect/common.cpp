#include "common.h"

static ULONG g_processNameOffset = 0;

BOOL InitGetProcessNameOffset()
{
    PEPROCESS curProc = PsGetCurrentProcess();
    for (int i = 0; i < 3 * PAGE_SIZE; ++i)
    {
        if (0 == strncmp(CHEAT_ENGINE_PROCESS_NAME, (PCHAR)curProc + i, strlen(CHEAT_ENGINE_PROCESS_NAME)))
        {
            g_processNameOffset = i;
            break;
        }
    }

    return (g_processNameOffset != 0);
}

VOID GetProcessName(IN PEPROCESS proc, OUT PCHAR procName)
{
    strcpy(procName, (PCHAR)proc + g_processNameOffset);
    return;
}

PSYSTEM_MODULE_INFORMATION GetSystemModuleInformation()
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    PVOID pBuffer = NULL;
    PSYSTEM_MODULE_INFORMATION pSystemModuleInformation = NULL;
    ULONG ulBufferSize = 0x2000;//初始分配内存的大小
    ULONG ulNeedSize = 0;

    do
    {
        pBuffer = ExAllocatePoolWithTag(NonPagedPool, ulBufferSize, MEM_TAG);
        ntStatus = ZwQuerySystemInformation(SystemModuleInformation, pBuffer, ulBufferSize, &ulNeedSize);
        if (STATUS_INFO_LENGTH_MISMATCH == ntStatus)
        {
            ExFreePool(pBuffer);
            pBuffer = NULL;
            ulBufferSize *= 2;
        }
        else if (!NT_SUCCESS(ntStatus))
        {
            ExFreePool(pBuffer);
            pBuffer = NULL;
            KdPrint(("%s %d: ZwQuerySystemInformation Failed %x", __FUNCTION__, __LINE__, ntStatus));
        }
    } while (ntStatus == STATUS_INFO_LENGTH_MISMATCH);

    pSystemModuleInformation = (PSYSTEM_MODULE_INFORMATION)pBuffer;

    return pSystemModuleInformation;
}

PVOID GetSSDTFunctionAddress(IN CHAR* functionName)
{
    BOOLEAN bReturn = TRUE;
    PEPROCESS pSystemEprocess = NULL;
    KAPC_STATE ApcState;
    ULONG i = 0;
    PVOID moduleStart = NULL;
    PSYSTEM_MODULE_INFORMATION pSystemModuleInformation = NULL;

    PIMAGE_DOS_HEADER pImageDosHeader = NULL;
    PIMAGE_NT_HEADERS64 pImageNTHeaders = NULL;
    PIMAGE_FILE_HEADER pImageFileHeader = NULL;
    PIMAGE_OPTIONAL_HEADER64 pImageOptionalHeader = NULL;
    PIMAGE_DATA_DIRECTORY pImageDataDirectory = NULL;
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
    ULONG ulNumberOfExportFunctions = 0;
    ULONG j = 0;
    WORD wIndex = 0;
    LONG64 xlFuncAddr = 0;
    LONG64 xlFuncNameAddr = 0;

    //输入参数校验
    if (NULL == functionName)
    {
        return NULL;
    }

    //获取system进程的进程块地址
    if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)4, &pSystemEprocess)))
    {
        return FALSE;
    }

    //附着到system进程
    KeStackAttachProcess(pSystemEprocess, &ApcState);

    //获取ntdll模块起始地址moduleStart
    pSystemModuleInformation = GetSystemModuleInformation();
    if (NULL == pSystemModuleInformation)
    {
        KdPrint(("%s %d: GetSytemModuleInformation\n", __FUNCTION__, __LINE__));
        bReturn = FALSE;
        goto End;
    }
    for (i = 0; i < pSystemModuleInformation->Count; ++i)
    {
        if (_stricmp(pSystemModuleInformation->Module[i].ImageName + pSystemModuleInformation->Module[i].ModuleNameOffset, "ntdll.dll") == 0)
        {
            moduleStart = pSystemModuleInformation->Module[i].Base;
            break;
        }
    }
    if (i == pSystemModuleInformation->Count)
    {
        KdPrint(("%s %d: Can't find ntdll.dll\n", __FUNCTION__, __LINE__));
        ExFreePool(pSystemModuleInformation);
        bReturn = FALSE;
        goto End;
    }
    ExFreePool(pSystemModuleInformation);

    // IMAGE_DOS_HEADER
    pImageDosHeader = (PIMAGE_DOS_HEADER)moduleStart;
    if (!MmIsAddressValid((PVOID)pImageDosHeader))
    {
        KdPrint(("%s %d: MmIsAddressValid Failed\n", __FUNCTION__, __LINE__));
        bReturn = FALSE;
        goto End;
    }

    // IMAGE_NT_HEADERS
    pImageNTHeaders = (PIMAGE_NT_HEADERS64)((LONG64)pImageDosHeader + pImageDosHeader->e_lfanew);
    if (!MmIsAddressValid((PVOID)pImageNTHeaders))
    {
        KdPrint(("%s %d: MmIsAddressValid Failed\n", __FUNCTION__, __LINE__));
        bReturn = FALSE;
        goto End;
    }

    // IMAGE_FILE_HEADER
    pImageFileHeader = &pImageNTHeaders->FileHeader;
    if (!MmIsAddressValid((PVOID)pImageFileHeader))
    {
        KdPrint(("%s %d: MmIsAddressValid Failed\n", __FUNCTION__, __LINE__));
        bReturn = FALSE;
        goto End;
    }

    // IMAGE_OPTIONAL_HEADER
    pImageOptionalHeader = &pImageNTHeaders->OptionalHeader;
    if (!MmIsAddressValid((PVOID)pImageOptionalHeader))
    {
        KdPrint(("%s %d: MmIsAddressValid Failed\n", __FUNCTION__, __LINE__));
        bReturn = FALSE;
        goto End;
    }

    // IMAGE_DATA_DIRECTORY
    pImageDataDirectory = pImageOptionalHeader->DataDirectory;
    if (!MmIsAddressValid((PVOID)pImageDataDirectory))
    {
        KdPrint(("%s %d: MmIsAddressValid Failed\n", __FUNCTION__, __LINE__));
        bReturn = FALSE;
        goto End;
    }

    // IMAGE_EXPORT_DIRECTORY
    pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((LONG64)pImageDosHeader + (DWORD)pImageDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (!MmIsAddressValid((PVOID)pImageExportDirectory))
    {
        KdPrint(("%s %d: MmIsAddressValid Failed\n", __FUNCTION__, __LINE__));
        bReturn = FALSE;
        goto End;
    }

    // 导出有名称的函数的数量
    ulNumberOfExportFunctions = pImageExportDirectory->NumberOfNames;

    // 遍历所有有名称的导出函数并找到匹配的函数
    for (j = 0; j < ulNumberOfExportFunctions; ++j)
    {
        //获取函数地址xlFuncAddr
        wIndex = (WORD) * (PWORD)((LONG64)pImageDosHeader + pImageExportDirectory->AddressOfNameOrdinals + j * sizeof(WORD));
        xlFuncAddr = (LONG64)pImageDosHeader + (DWORD) * (PDWORD)((LONG64)pImageDosHeader + pImageExportDirectory->AddressOfFunctions + wIndex * sizeof(DWORD));

        //获取函数名
        xlFuncNameAddr = (LONG64)pImageDosHeader + (LONG64)(DWORD) * (PDWORD)((LONG64)pImageDosHeader + pImageExportDirectory->AddressOfNames + j * sizeof(ULONG));
        if (!MmIsAddressValid(xlFuncNameAddr))
        {
            continue;
        }

        //进行匹配
        if (ulId == (ULONG) * (ULONG*)(xlFuncAddr + 4) && _strnicmp((const char*)xlFuncNameAddr, "ZW", 2) == 0)
        {
            break;
        }
    }
    if (j == ulNumberOfExportFunctions)
    {
        KdPrint(("%s %d: Can't find the SSDT Function %d\n", __FUNCTION__, __LINE__, ulId));
        bReturn = FALSE;
        goto End;
    }

    //获取函数名
    strcpy(functionName, (PCHAR)xlFuncNameAddr);
    functionName[0] = 'N';
    functionName[1] = 't';

End:
    //解除附着
    KeUnstackDetachProcess(&ApcState);

    //进程块解引用
    ObDereferenceObject(pSystemEprocess);

    return bReturn;
}
