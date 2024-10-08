#include "InjectDll.h"

typedef _Null_terminated_ CHAR* PSZ;
typedef _Null_terminated_ CONST char* PCSZ;

typedef struct _STRING
{
    USHORT Length;
    USHORT MaximumLength;
#ifdef MIDL_PASS
    [size_is(MaximumLength), length_is(Length)]
#endif // MIDL_PASS
        _Field_size_bytes_part_opt_(MaximumLength, Length) PCHAR Buffer;
} STRING;
typedef STRING* PSTRING;
typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;

typedef STRING CANSI_STRING;
typedef PSTRING PCANSI_STRING;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
#ifdef MIDL_PASS
    [size_is(MaximumLength / 2), length_is((Length) / 2)] USHORT* Buffer;
#else // MIDL_PASS
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH   Buffer;
#endif // MIDL_PASS
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef NTSTATUS(WINAPI* FUN_LDRGETPROCEDUREADDRESS)(IN PVOID DllHandle, IN PANSI_STRING ProcedureName OPTIONAL, IN ULONG ProcedureNumber OPTIONAL, OUT FARPROC* ProcedureAddress);
typedef VOID(WINAPI* RTLFREEUNICODESTRING)(_Inout_ PUNICODE_STRING UnicodeString);
typedef VOID(WINAPI* FUN_RTLINITANSISTRING)(_Out_    PANSI_STRING DestinationString, _In_opt_ PCSZ SourceString);
typedef NTSTATUS(WINAPI* FUN_RTLANSISTRINGTOUNICODESTRING)(_Inout_ PUNICODE_STRING DestinationString, _In_ PCANSI_STRING SourceString, _In_ BOOLEAN AllocateDestinationString);
typedef NTSTATUS(WINAPI* FUN_LDRLOADDLL)(PWCHAR, PULONG, PUNICODE_STRING, PHANDLE);
typedef BOOL(APIENTRY* DLLMAIN)(LPVOID, DWORD, LPVOID);
typedef NTSTATUS(WINAPI* FUN_NTALLOCATEVIRTUALMEMORY)(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN ULONG ZeroBits, IN OUT PSIZE_T RegionSize, IN ULONG AllocationType, IN ULONG Protect);
typedef INT(WINAPI* MESSAGEBOXA)(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType);

typedef struct _INJECTPARAM
{
    PVOID lpFileData;   // 我们要注射的DLL内容
    DWORD dwDataLength; // 我们要注射的DLL长度
    DWORD dwTargetPID;  // 我们要注射的进程PID

    FUN_LDRGETPROCEDUREADDRESS       fun_LdrGetProcedureAddress;
    FUN_NTALLOCATEVIRTUALMEMORY      fun_NtAllocateVirtualMemory;
    FUN_LDRLOADDLL                   fun_LdrLoadDll;
    FUN_RTLINITANSISTRING            fun_RtlInitAnsiString;
    FUN_RTLANSISTRINGTOUNICODESTRING fun_RtlAnsiStringToUnicodeString;
    RTLFREEUNICODESTRING			 fun_RtlFreeUnicodeString;
    MESSAGEBOXA						 fun_MessageBoxA;
} INJECTPARAM;

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
	// MESSAGEBOXA Func_MessageBoxA = InjectParam->fun_MessageBoxA;

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
        ULONG ImageSize = pNtHeader->OptionalHeader.SizeOfImage;   // 0x0001F000

        /*
        ULONG nAlign = pNtHeader->OptionalHeader.SectionAlignment; // 0x1000
        // 计算头们大小(Dos头 + Coff头 + PE头 + 数据目录表)
        ULONG HeaderSize = (pNtHeader->OptionalHeader.SizeOfHeaders + nAlign - 1) / nAlign * nAlign;
        ImageSize = HeaderSize;
        for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
        {
            // 得到该节的大小
            int VirtualSize = pSectionHeader[i].Misc.VirtualSize;
            int SizeOfRawData = pSectionHeader[i].SizeOfRawData;

            int MaxSize = (SizeOfRawData > VirtualSize) ? SizeOfRawData : VirtualSize;

            int SectionSize = (pSectionHeader[i].VirtualAddress + MaxSize + nAlign - 1) / nAlign * nAlign;

            if (ImageSize < SectionSize)
            {
                ImageSize = SectionSize;  // 取的最后的Section的地址+大小(跑到文件最后的末尾了)
            }
        }
        if (0 == ImageSize)
        {
            break;  // 文件大小没获取成功
        }
        */

        // 申请内存空间
        SIZE_T uSize = ImageSize;
        fun_NtAllocateVirtualMemory((HANDLE)-1, &pMemoryAddress, 0, &uSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (NULL == pMemoryAddress)
        {
            break;
        }

        // func_MessageBoxA(NULL, NULL, NULL, MB_OK);
        int Headers_Size = pNtHeader->OptionalHeader.SizeOfHeaders;
        int Sections_Size = pNtHeader->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
        int Move_Size = Headers_Size + Sections_Size;

        // 复制头和节区头的信息
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
            for (int k = 0; k < pSectionHeader[i].SizeOfRawData; ++k)
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
            func_DllMain(pMemoryAddress, DLL_PROCESS_ATTACH, pMemoryAddress);
        }
	} while (false);

	return 0;
}

static void MemoryLoadLibrary_End()
{
	LOG("MemoryLoadLibrary_End\r\n");
}

bool InjectDll::RemoteInjectDll(DWORD pid, LPCWSTR injectedDllPath)
{
	HANDLE hTargetProcess = NULL;
	PVOID pFileBuffer = NULL;
	PVOID pShellCodeBuffer = NULL;

	PBYTE pStartAddress = NULL;

	HANDLE hRemoteThread = NULL;

	do 
	{
		// 打开目标进程
        hTargetProcess = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            FALSE,
            pid
        );
        if (NULL == hTargetProcess)
        {
            LOG("OpenProcess failed");
            break;
        }

		// 文件buffer
        DWORD dwFileSize = 0;
		pFileBuffer = tool::LoadFileToMemory(injectedDllPath, dwFileSize);
        if (NULL == pFileBuffer || 0 == dwFileSize)
        {
            LOG("LoadFileToMemory failed");
			break;
        }

		// shellcode
        WORD* pShellCodeBegin = (WORD*)MemoryLoadLibrary_Begin;
        //----
        // 	while (*pShellCodeBegin != 0xCCCC)
        // 	{
        // 		pShellCodeBegin++;
        // 		ShellCodeSize += 2;
        // 	}
        //----或者这样取ShellCode长度
        DWORD shellCodeSize = (ULONG_PTR)MemoryLoadLibrary_End - (ULONG_PTR)MemoryLoadLibrary_Begin;
        pShellCodeBuffer = malloc(shellCodeSize);
		if (NULL == pShellCodeBuffer)
		{
            LOG("malloc failed");
            break;
		}
        RtlCopyMemory(pShellCodeBuffer, MemoryLoadLibrary_Begin, shellCodeSize);  // 拷贝ShellCode代码长度

		// 参数
        INJECTPARAM injectParam;
        RtlZeroMemory(&injectParam, sizeof(INJECTPARAM));
        injectParam.dwDataLength = dwFileSize;
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (NULL == hNtdll)
        {
            LOG("GetModuleHandleA failed");
			break;
        }
        injectParam.fun_LdrGetProcedureAddress = (FUN_LDRGETPROCEDUREADDRESS)GetProcAddress(hNtdll, "LdrGetProcedureAddress");
        injectParam.fun_NtAllocateVirtualMemory = (FUN_NTALLOCATEVIRTUALMEMORY)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
        injectParam.fun_LdrLoadDll = (FUN_LDRLOADDLL)GetProcAddress(hNtdll, "LdrLoadDll");
        injectParam.fun_RtlInitAnsiString = (FUN_RTLINITANSISTRING)GetProcAddress(hNtdll, "RtlInitAnsiString");
        injectParam.fun_RtlAnsiStringToUnicodeString = (FUN_RTLANSISTRINGTOUNICODESTRING)GetProcAddress(hNtdll, "RtlAnsiStringToUnicodeString");
        injectParam.fun_RtlFreeUnicodeString = (RTLFREEUNICODESTRING)GetProcAddress(hNtdll, "RtlFreeUnicodeString");

#define LOCAL_TEST 1
#if LOCAL_TEST
        injectParam.lpFileData = pFileBuffer;
        MemoryLoadLibrary_Begin(&injectParam);
#else
        // 申请内存，把Shellcode和DLL数据，和参数复制到目标进程
		// 安全起见，大小多加0x100
        pStartAddress = (PBYTE)VirtualAllocEx(hTargetProcess, 0, dwFileSize + 0x100 + shellCodeSize + sizeof(injectParam), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (NULL == pStartAddress)
		{
            LOG("VirtualAllocEx failed");
            break;
		}
        injectParam.lpFileData = pStartAddress;

		// 写入dll文件
		SIZE_T dwWrited = 0;
		if (!WriteProcessMemory(hTargetProcess, pStartAddress, pFileBuffer, dwFileSize, &dwWrited))
		{
            LOG("WriteProcessMemory failed");
            break;
		}
		// 写入shellcode
        PBYTE pShellCodeAddress = pStartAddress + dwFileSize + 0x100;
        WriteProcessMemory(hTargetProcess, pShellCodeAddress, pShellCodeBuffer, shellCodeSize, &dwWrited);
		// 写入参数
        PBYTE pShellCodeParamAddress = pStartAddress + dwFileSize + 0x100 + shellCodeSize;
        WriteProcessMemory(hTargetProcess, pShellCodeParamAddress, &injectParam, sizeof(injectParam), &dwWrited);

		// 创建远程线程
        HANDLE hRemoteThread = CreateRemoteThread(hTargetProcess, 0, 0, (LPTHREAD_START_ROUTINE)pShellCodeAddress, pShellCodeParamAddress, 0, 0);
		if (NULL == hRemoteThread)
		{
            LOG("CreateRemoteThread failed");
            break;
		}

		// 等待远程线程结束
		DWORD dwExitCode = 0;
        WaitForSingleObject(hRemoteThread, -1);
        GetExitCodeThread(hRemoteThread, &dwExitCode);
#endif
	} while (false);

	if (hRemoteThread)
	{
		CloseHandle(hRemoteThread);
	}

	if (pStartAddress)
	{
		VirtualFreeEx(hTargetProcess, pStartAddress, 0, MEM_FREE);
	}

	if (pShellCodeBuffer)
	{
		free(pShellCodeBuffer);
	}

	if (pFileBuffer)
	{
		free(pFileBuffer);
	}

    if (hTargetProcess)
    {
        CloseHandle(hTargetProcess);
    }

	return true;
}
