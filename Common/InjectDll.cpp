#include "InjectDll.h"

#include "../Shellcode/shellcode.h"

bool InjectDll::RemoteInjectDll(DWORD pid, LPCWSTR injectedDllPath)
{
    bool result = false;

	HANDLE hTargetProcess = NULL;
	PVOID pFileBuffer = NULL;
	PVOID pShellcodeBuffer = NULL;

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
        DWORD shellcodeSize = 0;
        pShellcodeBuffer = GetShellCodeBuffer(shellcodeSize);
        if (NULL == pShellcodeBuffer)
        {
            LOG("GetShellCodeBuffer failed");
            break;
        }
        LOG("Shellcode size: %d", shellcodeSize);

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
        if (NULL == injectParam.fun_LdrGetProcedureAddress ||
            NULL == injectParam.fun_NtAllocateVirtualMemory ||
            NULL == injectParam.fun_LdrLoadDll ||
            NULL == injectParam.fun_RtlInitAnsiString ||
            NULL == injectParam.fun_RtlAnsiStringToUnicodeString ||
            NULL == injectParam.fun_RtlFreeUnicodeString)
        {
            LOG("GetProcAddress failed");
            break;
        }

#if LOCAL_TEST
        injectParam.lpFileData = pFileBuffer;
        MemoryLoadLibrary_Begin(&injectParam);
#else
        // 申请内存，把Shellcode和DLL数据，和参数复制到目标进程
		// 安全起见，大小多加0x100
        SIZE_T totalSize = dwFileSize + 0x100 + shellcodeSize + sizeof(injectParam);
        pStartAddress = (PBYTE)VirtualAllocEx(hTargetProcess, 0, totalSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (NULL == pStartAddress)
		{
            LOG("VirtualAllocEx failed");
            break;
		}
        injectParam.lpFileData = pStartAddress;
        LOG("TotalSize: %d, DllFileSize: %d, ShellCodeSize: %d, ParamSize: %d",
            totalSize, dwFileSize, shellcodeSize, sizeof(injectParam));

		// 写入dll文件
		SIZE_T dwWrited = 0;
		if (!WriteProcessMemory(hTargetProcess, pStartAddress, pFileBuffer, dwFileSize, &dwWrited))
		{
            LOG("WriteProcessMemory failed");
            break;
		}
		// 写入shellcode
        PBYTE pShellcodeAddress = pStartAddress + dwFileSize + 0x100;
        if (!WriteProcessMemory(hTargetProcess, pShellcodeAddress, pShellcodeBuffer, shellcodeSize, &dwWrited))
        {
            LOG("WriteProcessMemory failed");
            break;
        }
		// 写入参数
        PBYTE pShellCodeParamAddress = pStartAddress + dwFileSize + 0x100 + shellcodeSize;
        if (!WriteProcessMemory(hTargetProcess, pShellCodeParamAddress, &injectParam, sizeof(injectParam), &dwWrited))
        {
            LOG("WriteProcessMemory failed");
            break;
        }

        LOG("StartAddress: 0x%llx, ShellCodeAddress: 0x%llx, ShellCodeParamAddress: 0x%llx",
            pStartAddress, pShellcodeAddress, pShellCodeParamAddress);

		// 创建远程线程
        hRemoteThread = CreateRemoteThread(hTargetProcess, 0, 0, (LPTHREAD_START_ROUTINE)pShellcodeAddress, pShellCodeParamAddress, 0, 0);
		if (NULL == hRemoteThread)
		{
            LOG("CreateRemoteThread failed");
            break;
		}

		// 等待远程线程结束
		DWORD dwExitCode = 0;
        WaitForSingleObject(hRemoteThread, -1);
        GetExitCodeThread(hRemoteThread, &dwExitCode);

        LOG("Remote Thread Exit, exit code: %d", dwExitCode);
#endif

        result = true;
	} while (false);

	if (hRemoteThread)
	{
		CloseHandle(hRemoteThread);
	}

	if (pStartAddress)
	{
		VirtualFreeEx(hTargetProcess, pStartAddress, 0, MEM_FREE);
	}

	if (pShellcodeBuffer)
	{
		free(pShellcodeBuffer);
	}

	if (pFileBuffer)
	{
		free(pFileBuffer);
	}

    if (hTargetProcess)
    {
        CloseHandle(hTargetProcess);
    }

	return result;
}
