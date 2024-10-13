#include "../Common/common.h"

BOOL CreateFullDump(HANDLE hProcess, DWORD pid, const char* dumpFilePath)
{
    // 创建转储文件
    HANDLE hDumpFile = CreateFileA(dumpFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hDumpFile)
    {
        OutputDebugStringA("CreateFileA failed");
        return FALSE;
    }

    // 写入转储文件
    BOOL success = MiniDumpWriteDump(
        hProcess,
        pid,
        hDumpFile,
        MiniDumpWithFullMemory,  // full dump
        NULL,
        NULL,
        NULL
    );
    if (!success)
    {
        OutputDebugStringA("MiniDumpWriteDump failed");
        CloseHandle(hDumpFile);
        return FALSE;
    }

    CloseHandle(hDumpFile);

    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        OutputDebugStringA("zxcvzxcvzxcv");
        if (!CreateFullDump(GetCurrentProcess(), GetCurrentProcessId(), "D:\\analyze\\PUBG\\TslGame.dmp"))
        {
            OutputDebugStringA("CreateFullDump failed");
        }
        else
        {
            OutputDebugStringA("CreateFullDump success");
        }
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
