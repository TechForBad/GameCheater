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
        // ��鳤��
        if (dwDataLength <= sizeof(IMAGE_DOS_HEADER))
        {
            break;
        }

        // ���Dosͷ
        PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(lpFileData);
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
            break;
        }

        // ��鳤��
        if (dwDataLength < pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS))
        {
            // ���Ȳ���(DOSͷ+NTͷ)
            break;
        }

        // ���Ntͷ
        PIMAGE_NT_HEADERS pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>((ULONG_PTR)lpFileData + pDosHeader->e_lfanew);
        if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
        {
            break;
        }
        if ((pNtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0)
        {
            // �������DLL
            break;
        }
        if ((pNtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0)
        {
            // �ļ�����ִ��
            break;
        }
        if (pNtHeader->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER))
        {
            // PE��ѡͷ���Ȳ���
            break;
        }

        // ��ȡ������ַ
        PIMAGE_SECTION_HEADER pSectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(((ULONG_PTR)pNtHeader + sizeof(IMAGE_NT_HEADERS)));

        // ��֤���������Ƿ���ȷ
        BOOL bSectionError = FALSE;
        for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
        {
            if ((pSectionHeader[i].PointerToRawData + pSectionHeader[i].SizeOfRawData) > dwDataLength)
            {
                // ��������ܳ���
                bSectionError = TRUE;
                break;
            }
        }
        if (bSectionError)
        {
            // �������ȳ��ֹ���
            break;
        }

        // ��ȡӳ���С
        ULONG ImageSize = pNtHeader->OptionalHeader.SizeOfImage;

        // �����ڴ�ռ�
        SIZE_T uSize = ImageSize;
        fun_NtAllocateVirtualMemory((HANDLE)-1, &pMemoryAddress, 0, &uSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (NULL == pMemoryAddress)
        {
            break;
        }

        // ����ͷ�ͽ���ͷ����Ϣ
        int Headers_Size = pNtHeader->OptionalHeader.SizeOfHeaders;
        int Sections_Size = pNtHeader->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
        int Move_Size = Headers_Size + Sections_Size;
        for (int i = 0; i < Move_Size; ++i)
        {
            (((PCHAR)pMemoryAddress)[i]) = (((PCHAR)lpFileData)[i]);
        }

        // ����ÿ������
        for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; ++i)
        {
            if ((NULL == pSectionHeader[i].VirtualAddress) || (NULL == pSectionHeader[i].SizeOfRawData))
            {
                // �����ַ���ߴ�СΪ0������
                continue;
            }

            // ��λ�ý������ڴ��е�λ��
            PVOID pSectionAddress = reinterpret_cast<PVOID>((ULONG_PTR)pMemoryAddress + pSectionHeader[i].VirtualAddress);

            // ���ƶ����ݵ������ڴ�
            for (int k = 0; k < pSectionHeader[i].SizeOfRawData; k++)
            {
                ((PCHAR)pSectionAddress)[k] = *((PCHAR)lpFileData + pSectionHeader[i].PointerToRawData + k);
            }
        }

        // �����ض�λ��
        if (pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress > 0 &&
            pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
        {
            ULONG_PTR Delta = (ULONG_PTR)pMemoryAddress - pNtHeader->OptionalHeader.ImageBase;
            PIMAGE_BASE_RELOCATION pBaseRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
                (ULONG_PTR)pMemoryAddress + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

            ULONG_PTR* pAddress = NULL;
            while ((pBaseRelocation->VirtualAddress + pBaseRelocation->SizeOfBlock) != 0)
            {
                // ���㱾����Ҫ�������ض�λ��(��ַ)����Ŀ
                int NumberOfReloc = (pBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

                WORD* pRelocationData = reinterpret_cast<WORD*>(((ULONG_PTR)pBaseRelocation + sizeof(IMAGE_BASE_RELOCATION)));

                for (int i = 0; i < NumberOfReloc; i++)
                {
                    if ((ULONG_PTR)(pRelocationData[i] & 0xF000 == 0x00003000) || (ULONG_PTR)(pRelocationData[i] & 0xF000) == 0x0000A000) // ��Ҫ�����ĵ�ַ
                    {
                        DWORD xxxx = pBaseRelocation->VirtualAddress + (pRelocationData[i] & 0x0FFF);
                        pAddress = (ULONG_PTR*)((ULONG_PTR)pMemoryAddress + xxxx);

                        *pAddress += Delta;
                    }
                }

                // ת�Ƶ���һ���ڽ��д���
                pBaseRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>((ULONG_PTR)pBaseRelocation + pBaseRelocation->SizeOfBlock);
            }
        }

        // ����IAT��
        ULONG_PTR ImportOffset = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (0 == ImportOffset)
        {
            // û�е����
            break;
        }
        PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(((ULONG_PTR)pMemoryAddress + ImportOffset));
        PIMAGE_IMPORT_BY_NAME pImportByName = NULL;
        while (pImportDescriptor->Characteristics != 0)
        {
            HANDLE hDll = NULL;

            // ��ȡDll����
            ANSI_STRING AnsiStr = { 0 };
            UNICODE_STRING UnicodeStr = { 0 };
            char* pDllName = reinterpret_cast<char*>((ULONG_PTR)pMemoryAddress + pImportDescriptor->Name);
            fun_RtlInitAnsiString(&AnsiStr, pDllName);
            fun_RtlAnsiStringToUnicodeString(&UnicodeStr, (PCANSI_STRING)&AnsiStr, true);
            fun_LdrLoadDll(NULL, NULL, &UnicodeStr, &hDll);  // �������DLL��Ҫ������DLL
            fun_RtlFreeUnicodeString(&UnicodeStr);
            if (NULL == hDll)
            {
                break;  // ������DLLû�м��سɹ�
            }

            PIMAGE_THUNK_DATA pRealIAT = reinterpret_cast<PIMAGE_THUNK_DATA>((ULONG_PTR)pMemoryAddress + pImportDescriptor->FirstThunk);
            PIMAGE_THUNK_DATA pOriginalIAT = reinterpret_cast<PIMAGE_THUNK_DATA>((ULONG_PTR)pMemoryAddress + pImportDescriptor->OriginalFirstThunk);

            // ��ô�DLL��ÿһ�����뺯���ĵ�ַ,������䵼���
            int i = 0;
            while (true)
            {
                if (0 == pOriginalIAT[i].u1.Function)
                {
                    break;
                }

                FARPROC lpFunction = NULL;
                if (IMAGE_SNAP_BY_ORDINAL(pOriginalIAT[i].u1.Ordinal))  // �����ֵ�������ǵ������к�
                {
                    if (IMAGE_ORDINAL(pOriginalIAT[i].u1.Ordinal))
                    {
                        fun_LdrGetProcedureAddress(hDll, NULL, IMAGE_ORDINAL(pOriginalIAT[i].u1.Ordinal), &lpFunction);
                    }
                }
                else
                {
                    // ��ȡ��IAT�������ĺ�������
                    pImportByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(((ULONG_PTR)pMemoryAddress + pOriginalIAT[i].u1.AddressOfData));
                    if (pImportByName->Name)
                    {
                        fun_RtlInitAnsiString(&AnsiStr, pImportByName->Name);
                        fun_LdrGetProcedureAddress(hDll, &AnsiStr, 0, &lpFunction);
                    }
                }

                if (lpFunction != NULL)  // �ҵ���
                {
                    pRealIAT[i].u1.Function = (ULONG_PTR)lpFunction;
                }
                else
                {
                    break;
                }

                ++i;
            }

            // ת�Ƶ���һ�������������
            pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)pImportDescriptor + sizeof(IMAGE_IMPORT_DESCRIPTOR));
        }

        // ��������ַ
        pNtHeader->OptionalHeader.ImageBase = (ULONG_PTR)pMemoryAddress;

        // ����dll
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
