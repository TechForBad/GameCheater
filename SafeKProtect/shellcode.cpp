#include "shellcode.h"

static ULONG_PTR WINAPI MemoryLoadLibrary_Begin(INJECTPARAM* InjectParam)
{
    LPVOID lpFileData = InjectParam->lpFileData;
    DWORD  dwDataLength = InjectParam->dwDataLength;

    FUN_LDRGETPROCEDUREADDRESS fun_LdrGetProcedureAddress = InjectParam->fun_LdrGetProcedureAddress;
    FUN_NTALLOCATEVIRTUALMEMORY fun_NtAllocateVirtualMemory = (InjectParam->fun_NtAllocateVirtualMemory);
    FUN_LDRLOADDLL fun_LdrLoadDll = (InjectParam->fun_LdrLoadDll);
    FUN_RTLINITANSISTRING fun_RtlInitAnsiString = InjectParam->fun_RtlInitAnsiString;
    FUN_RTLANSISTRINGTOUNICODESTRING fun_RtlAnsiStringToUnicodeString = InjectParam->fun_RtlAnsiStringToUnicodeString;
    RTLFREEUNICODESTRING fun_RtlFreeUnicodeString = InjectParam->fun_RtlFreeUnicodeString;

    DLLMAIN func_DllMain = NULL;

    PVOID pMemoryAddress = NULL;

    do
    {
        // 检查长度
        if (dwDataLength <= sizeof(IMAGE_DOS_HEADER))
        {
            break;
        }

        // 检查Dos头
        PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(lpFileData);
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
            break;
        }

        // 检查长度
        if (dwDataLength < pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS))
        {
            // 长度不够(DOS头+NT头)
            break;
        }

        // 检查Nt头
        PIMAGE_NT_HEADERS pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>((ULONG_PTR)lpFileData + pDosHeader->e_lfanew);
        if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
        {
            break;
        }
        if ((pNtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0)
        {
            // 如果不是DLL
            break;
        }
        if ((pNtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0)
        {
            // 文件不可执行
            break;
        }
        if (pNtHeader->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER))
        {
            // PE可选头长度不对
            break;
        }

        // 获取节区地址
        PIMAGE_SECTION_HEADER pSectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(((ULONG_PTR)pNtHeader + sizeof(IMAGE_NT_HEADERS)));

        // 验证节区长度是否都正确
        BOOL bSectionError = FALSE;
        for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
        {
            if ((pSectionHeader[i].PointerToRawData + pSectionHeader[i].SizeOfRawData) > dwDataLength)
            {
                // 如果超过总长度
                bSectionError = TRUE;
                break;
            }
        }
        if (bSectionError)
        {
            // 节区长度出现故障
            break;
        }

        // 获取映像大小
        ULONG ImageSize = pNtHeader->OptionalHeader.SizeOfImage;

        // 申请内存空间
        SIZE_T uSize = ImageSize;
        fun_NtAllocateVirtualMemory((HANDLE)-1, &pMemoryAddress, 0, &uSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (NULL == pMemoryAddress)
        {
            break;
        }

        // 复制头和节区头的信息
        int Headers_Size = pNtHeader->OptionalHeader.SizeOfHeaders;
        int Sections_Size = pNtHeader->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
        int Move_Size = Headers_Size + Sections_Size;
        for (int i = 0; i < Move_Size; ++i)
        {
            (((PCHAR)pMemoryAddress)[i]) = (((PCHAR)lpFileData)[i]);
        }

        // 复制每个节区
        for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; ++i)
        {
            if ((NULL == pSectionHeader[i].VirtualAddress) || (NULL == pSectionHeader[i].SizeOfRawData))
            {
                // 虚拟地址或者大小为0则跳过
                continue;
            }

            // 定位该节所在内存中的位置
            PVOID pSectionAddress = reinterpret_cast<PVOID>((ULONG_PTR)pMemoryAddress + pSectionHeader[i].VirtualAddress);

            // 复制段数据到虚拟内存
            for (int k = 0; k < pSectionHeader[i].SizeOfRawData; k++)
            {
                ((PCHAR)pSectionAddress)[k] = *((PCHAR)lpFileData + pSectionHeader[i].PointerToRawData + k);
            }
        }

        // 修正重定位表
        if (pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress > 0 &&
            pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
        {
            ULONG_PTR Delta = (ULONG_PTR)pMemoryAddress - pNtHeader->OptionalHeader.ImageBase;
            PIMAGE_BASE_RELOCATION pBaseRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
                (ULONG_PTR)pMemoryAddress + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

            ULONG_PTR* pAddress = NULL;
            while ((pBaseRelocation->VirtualAddress + pBaseRelocation->SizeOfBlock) != 0)
            {
                // 计算本节需要修正的重定位项(地址)的数目
                int NumberOfReloc = (pBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

                WORD* pRelocationData = reinterpret_cast<WORD*>(((ULONG_PTR)pBaseRelocation + sizeof(IMAGE_BASE_RELOCATION)));

                for (int i = 0; i < NumberOfReloc; i++)
                {
                    if ((ULONG_PTR)(pRelocationData[i] & 0xF000 == 0x00003000) || (ULONG_PTR)(pRelocationData[i] & 0xF000) == 0x0000A000) // 需要修正的地址
                    {
                        DWORD xxxx = pBaseRelocation->VirtualAddress + (pRelocationData[i] & 0x0FFF);
                        pAddress = (ULONG_PTR*)((ULONG_PTR)pMemoryAddress + xxxx);

                        *pAddress += Delta;
                    }
                }

                // 转移到下一个节进行处理
                pBaseRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>((ULONG_PTR)pBaseRelocation + pBaseRelocation->SizeOfBlock);
            }
        }

        // 修正IAT表
        ULONG_PTR ImportOffset = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (0 == ImportOffset)
        {
            // 没有导入表
            break;
        }
        PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(((ULONG_PTR)pMemoryAddress + ImportOffset));
        PIMAGE_IMPORT_BY_NAME pImportByName = NULL;
        while (pImportDescriptor->Characteristics != 0)
        {
            HANDLE hDll = NULL;

            // 获取Dll名称
            ANSI_STRING AnsiStr = { 0 };
            UNICODE_STRING UnicodeStr = { 0 };
            char* pDllName = reinterpret_cast<char*>((ULONG_PTR)pMemoryAddress + pImportDescriptor->Name);
            fun_RtlInitAnsiString(&AnsiStr, pDllName);
            fun_RtlAnsiStringToUnicodeString(&UnicodeStr, (PCANSI_STRING)&AnsiStr, true);
            fun_LdrLoadDll(NULL, NULL, &UnicodeStr, &hDll);  // 加载这个DLL需要依赖的DLL
            fun_RtlFreeUnicodeString(&UnicodeStr);
            if (NULL == hDll)
            {
                break;  // 依赖的DLL没有加载成功
            }

            PIMAGE_THUNK_DATA pRealIAT = reinterpret_cast<PIMAGE_THUNK_DATA>((ULONG_PTR)pMemoryAddress + pImportDescriptor->FirstThunk);
            PIMAGE_THUNK_DATA pOriginalIAT = reinterpret_cast<PIMAGE_THUNK_DATA>((ULONG_PTR)pMemoryAddress + pImportDescriptor->OriginalFirstThunk);

            // 获得此DLL中每一个导入函数的地址,用来填充导入表
            int i = 0;
            while (true)
            {
                if (0 == pOriginalIAT[i].u1.Function)
                {
                    break;
                }

                FARPROC lpFunction = NULL;
                if (IMAGE_SNAP_BY_ORDINAL(pOriginalIAT[i].u1.Ordinal))  // 这里的值给出的是导出序列号
                {
                    if (IMAGE_ORDINAL(pOriginalIAT[i].u1.Ordinal))
                    {
                        fun_LdrGetProcedureAddress(hDll, NULL, IMAGE_ORDINAL(pOriginalIAT[i].u1.Ordinal), &lpFunction);
                    }
                }
                else
                {
                    // 获取此IAT所描述的函数名称
                    pImportByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(((ULONG_PTR)pMemoryAddress + pOriginalIAT[i].u1.AddressOfData));
                    if (pImportByName->Name)
                    {
                        fun_RtlInitAnsiString(&AnsiStr, pImportByName->Name);
                        fun_LdrGetProcedureAddress(hDll, &AnsiStr, 0, &lpFunction);
                    }
                }

                if (lpFunction != NULL)  // 找到了
                {
                    pRealIAT[i].u1.Function = (ULONG_PTR)lpFunction;
                }
                else
                {
                    break;
                }

                ++i;
            }

            // 转移到下一个导入表描述符
            pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)pImportDescriptor + sizeof(IMAGE_IMPORT_DESCRIPTOR));
        }

        // 修正基地址
        pNtHeader->OptionalHeader.ImageBase = (ULONG_PTR)pMemoryAddress;

        // 启动dll
        func_DllMain = reinterpret_cast<DLLMAIN>((ULONG_PTR)pMemoryAddress + pNtHeader->OptionalHeader.AddressOfEntryPoint);
        if (func_DllMain)
        {
            func_DllMain(pMemoryAddress, 1, pMemoryAddress);
        }
    } while (false);

    return 0;
}

static void MemoryLoadLibrary_End()
{
}

PVOID GetShellCodeBuffer(ULONG& shellCodeSize)
{
    shellCodeSize = (ULONG_PTR)MemoryLoadLibrary_End - (ULONG_PTR)MemoryLoadLibrary_Begin;
    return MemoryLoadLibrary_Begin;
}
