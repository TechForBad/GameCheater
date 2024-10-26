#include <windows.h>  
#include <stdio.h>

#include "../Common/common.h"

static DriverComm* g_pDriverComm = NULL;

bool test_createFullDumpByR3(DWORD pid)
{
    // 获取进程句柄
    HANDLE hProcHandle = NULL;
    if (!g_pDriverComm->GetHandleForProcessID(pid, &hProcHandle))
    {
        LOG("GetHandleForProcessID failed");
        return false;
    }

    LOG("pid: %d, handle: %d", pid, hProcHandle);

    // 创建full dump
    LPCSTR dumpeFilePath = "D:\\analyze\\PUBG\\TslGame.dmp";
    if (!tool::CreateFullDump(hProcHandle, pid, dumpeFilePath))
    {
        LOG("CreateFullDump failed");
        return false;
    }

    if (hProcHandle)
    {
        CloseHandle(hProcHandle);
    }

    return true;
}

bool test_createFullDumpByR0(DWORD pid)
{
    // 获取dll文件全路径
    wchar_t dumpPath[MAX_PATH] = { 0 };
    if (!tool::GetCurrentModuleDirPath(dumpPath))
    {
        LOG("GetCurrentModuleDirPath failed");
        return false;
    }
    wcscat(dumpPath, L"test.dmp");

    // 生成dump
    if (!g_pDriverComm->ProcessCallMiniDumpWriteDump(pid, dumpPath))
    {
        LOG("ProcessCallMiniDumpWriteDump failed");
        return false;
    }

    return true;
}

bool test_injectDllByR3(DWORD pid)
{
    // 获取dll文件全路径
    wchar_t dllFilePath[MAX_PATH] = { 0 };
    if (!tool::GetCurrentModuleDirPath(dllFilePath))
    {
        LOG("GetCurrentModuleDirPath failed");
        return false;
    }
    wcscat(dllFilePath, MY_DLL_NAME);

    // 注入dll
    if (!InjectDll::RemoteInjectDll(pid, dllFilePath))
    {
        LOG("RemoteInjectDll failed");
        return false;
    }

    return true;
}

bool test_injectDllByR0(DWORD pid)
{
    // 获取dll文件全路径
    wchar_t dllFilePath[MAX_PATH] = { 0 };
    if (!tool::GetCurrentModuleDirPath(dllFilePath))
    {
        LOG("GetCurrentModuleDirPath failed");
        return false;
    }
    wcscat(dllFilePath, MY_DLL_NAME);

    // 注入dll
    std::wstring dllFullPath = tool::Format(L"\\??\\%ws", dllFilePath);
    if (!g_pDriverComm->InjectDllWithNoModuleByEventHook(pid, dllFullPath.c_str()))
    {
        LOG("InjectDllWithNoModuleByEventHook failed");
        return false;
    }

    return true;
}

int main()
{
    // 输出重定向到父窗口控制台，方便观察打印日志
    AttachConsole(ATTACH_PARENT_PROCESS);
    if (NULL == freopen("CONOUT$", "w+t", stdout))
    {
        LOG("freopen failed");
        return -1;
    }

    // 提权
    if (!tool::AdjustProcessTokenPrivilege())
    {
        LOG("AdjustProcessTokenPrivilege failed");
        return -1;
    }

    // 初始化驱动通信
    g_pDriverComm = DriverComm::GetInstance();
    if (!g_pDriverComm->Init(true))
    {
        LOG("Init failed");
        return -1;
    }

    // 初始化VM
    g_pDriverComm->InitVm();

    /*
    // 输入进程号
    DWORD pid = 0;
    printf("Input Process Id: ");
    std::cin >> pid;
    printf("Output: %d\n", pid);

    DWORD pid = 0;
    if (!tool::GetProcessId(L"windbg.exe", &pid))
    {
        LOG("GetProcessId failed");
        return -1;
    }
    LOG("find process id: %d", pid);
    */

    return 0;
}
