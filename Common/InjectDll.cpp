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
    RTLFREEUNICODESTRING         fun_RtlFreeUnicodeString;
    MESSAGEBOXA                  Func_MessageBoxA;
} INJECTPARAM;

static ULONG_PTR WINAPI MemoryLoadLibrary_Begin(INJECTPARAM* InjectParam)
{
	LPVOID lpFileData = InjectParam->lpFileData;
	DWORD  dwDataLength = InjectParam->dwDataLength;

	FUN_LDRGETPROCEDUREADDRESS Func_LdrGetProcedureAddress = InjectParam->fun_LdrGetProcedureAddress;
	FUN_NTALLOCATEVIRTUALMEMORY Func_NtAllocateVirtualMemory = (InjectParam->fun_NtAllocateVirtualMemory);
	FUN_LDRLOADDLL Func_LdrLoadDll = (InjectParam->fun_LdrLoadDll);
	FUN_RTLINITANSISTRING Func_RtlInitAnsiString = InjectParam->fun_RtlInitAnsiString;
	FUN_RTLANSISTRINGTOUNICODESTRING Func_RtlAnsiStringToUnicodeString = InjectParam->fun_RtlAnsiStringToUnicodeString;
	RTLFREEUNICODESTRING Func_RtlFreeUnicodeString = InjectParam->fun_RtlFreeUnicodeString;
	//MESSAGEBOXA Func_MessageBoxA = InjectParam->Func_MessageBoxA;

	DLLMAIN Func_DllMain = NULL;

	PVOID pMemoryAddress = NULL;
	//-------------
	do
	{
		ULONG nAlign = 0; //节区对齐粒度
		ULONG HeaderSize = 0;
		ULONG ImageSize = 0;

		PIMAGE_DOS_HEADER pDosHeader = NULL;
		PIMAGE_NT_HEADERS pNtHeader = NULL;
		PIMAGE_SECTION_HEADER pSectionHeader = NULL;

		ANSI_STRING AnsiStr;
		UNICODE_STRING UnicodeStr;

		if (dwDataLength > sizeof(IMAGE_DOS_HEADER))
		{
			//Dos头
			pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(lpFileData);

			//检查Dos头是否有MZ标记
			if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			{
				break;  //不是Dos头
			}

			//检查长度
			if (dwDataLength < pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS))
			{
				break;  //长度不够(DOS头+NT头)
			}

			//Nt头
			pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>((ULONG_PTR)lpFileData + pDosHeader->e_lfanew);

			if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
			{
				break;  //不是NT头
			}

			if ((pNtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0)
			{
				break;  //如果不是DLL
			}

			if ((pNtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0)
			{
				break;   //文件不可执行
			}

			if (pNtHeader->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER))
			{
				break;   //PE可选头长度不对
			}

			//取得节区地址
			pSectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(((ULONG_PTR)pNtHeader + sizeof(IMAGE_NT_HEADERS)));

			BOOL bSectionError = FALSE;

			//验证节区长度是否都正确
			for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
			{
				if ((pSectionHeader[i].PointerToRawData + pSectionHeader[i].SizeOfRawData) > dwDataLength)
				{
					bSectionError = TRUE;
					break;  //如果超过总长度
				}
			}

			if (bSectionError)
			{
				break;  //节区长度出现故障
			}

			//
			nAlign = pNtHeader->OptionalHeader.SectionAlignment; //0x1000

			ImageSize = pNtHeader->OptionalHeader.SizeOfImage;   //0x0001F000
			//计算头们大小(Dos头 + Coff头 + PE头 + 数据目录表)
			HeaderSize = (pNtHeader->OptionalHeader.SizeOfHeaders + nAlign - 1) / nAlign * nAlign;

			ImageSize = HeaderSize;
			//
			for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
			{
				//得到该节的大小
				int VirtualSize = pSectionHeader[i].Misc.VirtualSize;
				int SizeOfRawData = pSectionHeader[i].SizeOfRawData;

				int MaxSize = (SizeOfRawData > VirtualSize) ? SizeOfRawData : VirtualSize;

				int SectionSize = (pSectionHeader[i].VirtualAddress + MaxSize + nAlign - 1) / nAlign * nAlign;

				if (ImageSize < SectionSize)
				{
					ImageSize = SectionSize;  //取的最后的Section的地址+大小(跑到文件最后的末尾了)
				}
			}

			if (ImageSize == 0)
			{
				break;  //文件大小没获取成功
			}

			//需要再当前进程里申请内存空间
			SIZE_T uSize = ImageSize;

			Func_NtAllocateVirtualMemory((HANDLE)-1, &pMemoryAddress, 0, &uSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

			if (pMemoryAddress != NULL)
			{
				int i = 0;
				//Func_MessageBoxA(NULL, NULL, NULL, MB_OK);
				int Headers_Size = pNtHeader->OptionalHeader.SizeOfHeaders;
				int Sections_Size = pNtHeader->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);

				int Move_Size = Headers_Size + Sections_Size;

				//复制头和节区头的信息
				for (i = 0; i < Move_Size; i++)
				{
					//*((PCHAR)pMemoryAddress + i) = *((PCHAR)lpFileData + i);
					(((PCHAR)pMemoryAddress)[i]) = (((PCHAR)lpFileData)[i]);
				}

				//复制每个节区
				for (i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
				{
					if (pSectionHeader[i].VirtualAddress == 0 || pSectionHeader[i].SizeOfRawData == 0)
					{
						continue;  //虚拟地址或者大小为0则跳过
					}

					//定位该节所在内存中的位置
					PVOID pSectionAddress = reinterpret_cast<PVOID>((ULONG_PTR)pMemoryAddress + pSectionHeader[i].VirtualAddress);

					// 复制段数据到虚拟内存
					for (int k = 0; k < pSectionHeader[i].SizeOfRawData; k++)
					{
						((PCHAR)pSectionAddress)[k] = *((PCHAR)lpFileData + pSectionHeader[i].PointerToRawData + k);
					}
				}
				//--------------
				//解析重定位表
				if (pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress > 0 &&
					pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
				{
					ULONG_PTR Delta = (ULONG_PTR)pMemoryAddress - pNtHeader->OptionalHeader.ImageBase;
					PIMAGE_BASE_RELOCATION pBaseRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>((ULONG_PTR)pMemoryAddress +
																									  pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

					//LOG("重定位表:%p\r\n", pBaseRelocation);

					ULONG_PTR* pAddress = NULL;

					while ((pBaseRelocation->VirtualAddress + pBaseRelocation->SizeOfBlock) != 0)
					{
						//计算本节需要修正的重定位项(地址)的数目
						int NumberOfReloc = (pBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
						//LOG("VirtualAddress:0x%X NumberOfReloc:0x%X\r\n", pBaseRelocation->VirtualAddress, NumberOfReloc);

						WORD* pRelocationData = reinterpret_cast<WORD*>(((ULONG_PTR)pBaseRelocation + sizeof(IMAGE_BASE_RELOCATION)));
						//LOG("pRelocationData:%p\r\n", pRelocationData);

						for (i = 0; i < NumberOfReloc; i++)
						{
							if ((ULONG_PTR)(pRelocationData[i] & 0xF000 == 0x00003000) || (ULONG_PTR)(pRelocationData[i] & 0xF000) == 0x0000A000) //需要修正的地址
							{
								DWORD xxxx = pBaseRelocation->VirtualAddress + (pRelocationData[i] & 0x0FFF);
								//LOG("修正前:0x%X 修正后:0x%X\r\n", pRelocationData[i], xxxx);
								pAddress = (ULONG_PTR*)((ULONG_PTR)pMemoryAddress + xxxx);

								*pAddress += Delta;
								//LOG("内存地址:%p\r\n", pAddress);
							}
						}

						//转移到下一个节进行处理
						pBaseRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>((ULONG_PTR)pBaseRelocation + pBaseRelocation->SizeOfBlock);
					}
				}
				//------------
				//修正IAT表
				ULONG_PTR ImportOffset = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
				if (ImportOffset == 0)
				{
					break;  //没有倒入表
				}

				PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(((ULONG_PTR)pMemoryAddress + ImportOffset));

				PIMAGE_IMPORT_BY_NAME pImportByName = NULL;

				while (pImportDescriptor->Characteristics != 0)
				{
					HANDLE hDll = NULL;

					//获取Dll名称
					char* pDllName = reinterpret_cast<char*>((ULONG_PTR)pMemoryAddress + pImportDescriptor->Name);
					//LOG("%s\r\n", pDllName);

					Func_RtlInitAnsiString(&AnsiStr, pDllName);

					Func_RtlAnsiStringToUnicodeString(&UnicodeStr, (PCANSI_STRING)&AnsiStr, true);

					Func_LdrLoadDll(NULL, NULL, &UnicodeStr, &hDll);  //加载这个DLL需要依赖的DLL

					Func_RtlFreeUnicodeString(&UnicodeStr);

					if (hDll == NULL)
					{
						break;  //依赖的DLL没有加载成功
					}

					PIMAGE_THUNK_DATA pRealIAT = reinterpret_cast<PIMAGE_THUNK_DATA>((ULONG_PTR)pMemoryAddress + pImportDescriptor->FirstThunk);
					PIMAGE_THUNK_DATA pOriginalIAT = reinterpret_cast<PIMAGE_THUNK_DATA>((ULONG_PTR)pMemoryAddress + pImportDescriptor->OriginalFirstThunk);

					//LOG("pRealIAT:%p  pOriginalIAT:%p\r\n", pRealIAT, pOriginalIAT);

					//获得此DLL中每一个导入函数的地址,用来填充导入表
					i = 0;
					while (true)
					{
						if (pOriginalIAT[i].u1.Function == 0)
						{
							break;
						}

						//LOG("Function:0x%X\r\n", pOriginalIAT[i].u1.Function);

						FARPROC lpFunction = NULL;

						if (IMAGE_SNAP_BY_ORDINAL(pOriginalIAT[i].u1.Ordinal)) //这里的值给出的是导出序列号
						{
							if (IMAGE_ORDINAL(pOriginalIAT[i].u1.Ordinal))
							{
								Func_LdrGetProcedureAddress(hDll, NULL, IMAGE_ORDINAL(pOriginalIAT[i].u1.Ordinal), &lpFunction);
								//LOG("Ordinal:0x%X:%p\r\n", pOriginalIAT[i].u1.Ordinal, lpFunction);
							}
						}
						else
						{
							//获取此IAT所描述的函数名称
							pImportByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(((ULONG_PTR)pMemoryAddress + pOriginalIAT[i].u1.AddressOfData));
							if (pImportByName->Name)
							{
								Func_RtlInitAnsiString(&AnsiStr, pImportByName->Name);
								Func_LdrGetProcedureAddress(hDll, &AnsiStr, 0, &lpFunction);
								//LOG("%s:0x%p\r\n", pImportByName->Name, lpFunction);
							}
						}

						if (lpFunction != NULL)  //找到了
						{
							//LOG("[1]--->%s:0x%p\r\n", pImportByName->Name, lpFunction);
							pRealIAT[i].u1.Function = (ULONG_PTR)lpFunction;
							//LOG("[2]--->%s:0x%p\r\n", pImportByName->Name, pRealIAT[i].u1.Function);
						}
						else
							break;

						i++;
					}

					//转移到下一个导入表描述符
					pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)pImportDescriptor + sizeof(IMAGE_IMPORT_DESCRIPTOR));
				}

				//修正基地址
				//LOG("[1]--->0x%p\r\n", pMemoryAddress);
				pNtHeader->OptionalHeader.ImageBase = (ULONG_PTR)pMemoryAddress;
				//LOG("[2]--->0x%p\r\n", pNtHeader->OptionalHeader.ImageBase);

				Func_DllMain = reinterpret_cast<DLLMAIN>((ULONG_PTR)pMemoryAddress + pNtHeader->OptionalHeader.AddressOfEntryPoint);

				if (Func_DllMain)
				{
					//LOG("DllMain入口:%p\r\n", Func_DllMain);

					Func_DllMain(pMemoryAddress, DLL_PROCESS_ATTACH, pMemoryAddress);
				}
			}
		}
	} while (false);
	//----------------

	return 0;
}

static void MemoryLoadLibrary_End()
{
	LOG("MemoryLoadLibrary_End\r\n");
}

bool InjectDll::RemoteInjectDll(DWORD pid, LPCWSTR injectedDllPath)
{
    SIZE_T dwWrited = 0;
    DWORD dwFileSize = sizeof(DllX64);

    WORD* pShellCodeBegin = (WORD*)MemoryLoadLibrary_Begin;
    //----
    // 	while (*pShellCodeBegin != 0xCCCC)
    // 	{
    // 		pShellCodeBegin++;
    // 		ShellCodeSize += 2;
    // 	}
    //----或者这样取ShellCode长度
    DWORD shellCodeSize = (ULONG_PTR)MemoryLoadLibrary_End - (ULONG_PTR)MemoryLoadLibrary_Begin;

    PVOID pShellCodeBuffer = malloc(shellCodeSize);
    RtlCopyMemory(pShellCodeBuffer, MemoryLoadLibrary_Begin, shellCodeSize);  //拷贝ShellCode代码长度

    INJECTPARAM injectParam;
    RtlZeroMemory(&injectParam, sizeof(INJECTPARAM));
    injectParam.dwDataLength = dwFileSize;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    injectParam.fun_LdrGetProcedureAddress = (FUN_LDRGETPROCEDUREADDRESS)GetProcAddress(hNtdll, "LdrGetProcedureAddress");
    injectParam.fun_NtAllocateVirtualMemory = (FUN_NTALLOCATEVIRTUALMEMORY)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    injectParam.fun_LdrLoadDll = (FUN_LDRLOADDLL)GetProcAddress(hNtdll, "LdrLoadDll");
    injectParam.fun_RtlInitAnsiString = (FUN_RTLINITANSISTRING)GetProcAddress(hNtdll, "RtlInitAnsiString");
    injectParam.fun_RtlAnsiStringToUnicodeString = (FUN_RTLANSISTRINGTOUNICODESTRING)GetProcAddress(hNtdll, "RtlAnsiStringToUnicodeString");
    injectParam.fun_RtlFreeUnicodeString = (RTLFREEUNICODESTRING)GetProcAddress(hNtdll, "RtlFreeUnicodeString");

#if LOCAL_TEST
    injectParam.lpFileData = DllX64;
    MemoryLoadLibrary_Begin(&injectParam);
    //LoadLibrary("DLL.dll");
#else
    //----------
// 	HMODULE hUser32Dll = LoadLibrary("User32.dll");
// 	InjectParam.Func_MessageBoxA = (MESSAGEBOXA)GetProcAddress(hUser32Dll, "MessageBoxA");
// 	LOG("MessageBoxA:0x%p\r\n", InjectParam.Func_MessageBoxA);
    //----------

	/*
    std::cout << termcolor::green << VMPSTRA("LdrGetProcedureAddress:0x") << std::dec << InjectParam.Func_LdrGetProcedureAddress << termcolor::reset << std::endl;
    std::cout << termcolor::green << VMPSTRA("NtAllocateVirtualMemory:0x") << std::dec << InjectParam.Func_NtAllocateVirtualMemory << termcolor::reset << std::endl;

    std::cout << termcolor::green << VMPSTRA("LdrLoadDll:0x") << std::dec << InjectParam.Func_LdrLoadDll << termcolor::reset << std::endl;
    std::cout << termcolor::green << VMPSTRA("RtlInitAnsiString:0x") << std::dec << InjectParam.Func_RtlInitAnsiString << termcolor::reset << std::endl;

    std::cout << termcolor::green << VMPSTRA("RtlAnsiStringToUnicodeString:0x") << std::dec << InjectParam.Func_RtlAnsiStringToUnicodeString << termcolor::reset << std::endl;
    std::cout << termcolor::green << VMPSTRA("RtlFreeUnicodeString:0x") << std::dec << InjectParam.Func_RtlFreeUnicodeString << termcolor::reset << std::endl;
	*/

    // 申请内存,把Shellcode和DLL数据,和参数复制到目标进程
    // 安全起见,大小多加0x100
    PBYTE pStartAddress = (PBYTE)VirtualAllocEx(TargetProcess, 0, dwFileSize + 0x100 + shellCodeSize + sizeof(injectParam), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    LOG("申请的内存空间 StartAddress:0x%p\r\n", pStartAddress);
    injectParam.lpFileData = pStartAddress;

    WriteProcessMemory(TargetProcess, pStartAddress, DllX64, dwFileSize, &dwWrited);

    LOG("写入DLL内容完毕\r\n");

    //-------------
    PBYTE ShellCodeAddress = pStartAddress + dwFileSize + 0x100;
    LOG("ShellCode写入的位置:0x%p\r\n", ShellCodeAddress);
    WriteProcessMemory(TargetProcess, ShellCodeAddress, pShellCodeBuffer, shellCodeSize, &dwWrited);
    //-------------
    PBYTE ShellCodeParamAddress = pStartAddress + dwFileSize + 0x100 + shellCodeSize;
    WriteProcessMemory(TargetProcess, ShellCodeParamAddress, &injectParam, sizeof(injectParam), &dwWrited);
    //-------------
    HANDLE hRemoteThread = CreateRemoteThread(TargetProcess, 0, 0, (LPTHREAD_START_ROUTINE)ShellCodeAddress, ShellCodeParamAddress, 0, 0);

    if (hRemoteThread)
    {
        DWORD dwExitCode = 0;
        WaitForSingleObject(hRemoteThread, -1);
        GetExitCodeThread(hRemoteThread, &dwExitCode);

        //释放掉申请的内存
        VirtualFreeEx(TargetProcess, pStartAddress, 0, MEM_FREE);
        CloseHandle(hRemoteThread);
    }
#endif

    if (pShellCodeBuffer)
    {
        free(pShellCodeBuffer);
    }

	return true;
}
