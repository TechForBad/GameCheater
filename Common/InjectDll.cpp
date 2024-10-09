#include "InjectDll.h"

#include "../Shellcode/shellcode.h"

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
        LOG("Dll file size: %d", dwFileSize);

        // shellcode
        DWORD shellCodeSize = (ULONG_PTR)MemoryLoadLibrary_End - (ULONG_PTR)MemoryLoadLibrary_Begin;
        pShellCodeBuffer = malloc(shellCodeSize);
		if (NULL == pShellCodeBuffer)
		{
            LOG("malloc failed");
            break;
		}
        RtlCopyMemory(pShellCodeBuffer, MemoryLoadLibrary_Begin, shellCodeSize);
        LOG("Shellcode size: %d", shellCodeSize);

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

#if LOCAL_TEST
        injectParam.lpFileData = pFileBuffer;
        MemoryLoadLibrary_Begin(&injectParam);
#else
        // 申请内存，把Shellcode和DLL数据，和参数复制到目标进程
		// 安全起见，大小多加0x100
        SIZE_T totalSize = dwFileSize + 0x100 + shellCodeSize + sizeof(injectParam);
        pStartAddress = (PBYTE)VirtualAllocEx(hTargetProcess, 0, totalSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (NULL == pStartAddress)
		{
            LOG("VirtualAllocEx failed");
            break;
		}
        injectParam.lpFileData = pStartAddress;
        LOG("TotalSize: %d, DllFileSize: %d, ShellCodeSize: %d, ParamSize: %d",
            totalSize, dwFileSize, shellCodeSize, sizeof(injectParam));

		// 写入dll文件
		SIZE_T dwWrited = 0;
		if (!WriteProcessMemory(hTargetProcess, pStartAddress, pFileBuffer, dwFileSize, &dwWrited))
		{
            LOG("WriteProcessMemory failed");
            break;
		}
		// 写入shellcode
        PBYTE pShellCodeAddress = pStartAddress + dwFileSize + 0x100;
        if (!WriteProcessMemory(hTargetProcess, pShellCodeAddress, pShellCodeBuffer, shellCodeSize, &dwWrited))
        {
            LOG("WriteProcessMemory failed");
            break;
        }
		// 写入参数
        PBYTE pShellCodeParamAddress = pStartAddress + dwFileSize + 0x100 + shellCodeSize;
        if (!WriteProcessMemory(hTargetProcess, pShellCodeParamAddress, &injectParam, sizeof(injectParam), &dwWrited))
        {
            LOG("WriteProcessMemory failed");
            break;
        }

        LOG("StartAddress: 0x%llx, ShellCodeAddress: 0x%llx, ShellCodeParamAddress: 0x%llx",
            pStartAddress, pShellCodeAddress, pShellCodeParamAddress);

		// 创建远程线程
        hRemoteThread = CreateRemoteThread(hTargetProcess, 0, 0, (LPTHREAD_START_ROUTINE)pShellCodeAddress, pShellCodeParamAddress, 0, 0);
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
