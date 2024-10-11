#include <windows.h>  
#include <stdio.h>

#include "../Common/common.h"

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
    DriverComm* pDriverComm = DriverComm::GetInstance();
    if (!pDriverComm->Init())
    {
        LOG("Init failed");
        return -1;
    }

    // 获取dwm进程号
    DWORD pid = 0;
    printf("Input Process Id: ");
    std::cin >> pid;
    printf("Output: %d\n", pid);

    /*
    if (!tool::GetProcessId(L"dwm.exe", &pid))
    {
        LOG("GetProcessId failed");
        return -1;
    }
    LOG("dwm process id: %d", pid);

    // 获取dll文件全路径
    wchar_t dllFilePath[MAX_PATH] = { 0 };
    if (!tool::GetCurrentModuleDirPath(dllFilePath))
    {
        LOG("GetCurrentModuleDirPath failed");
        return -1;
    }
    wcscat(dllFilePath, MY_DLL_NAME);

    // 远程注入dll
    if (!InjectDll::RemoteInjectDll(pid, dllFilePath))
    {
        LOG("RemoteInjectDll failed");
        return -1;
    }
    */

    // 获取进程句柄
    HANDLE hProcHandle = NULL;
    if (!pDriverComm->GetHandleForProcessID(pid, &hProcHandle))
    {
        LOG("GetHandleForProcessID failed");
        getchar();
        return -1;
    }

    LOG("pid: %d, handle: %d", pid, hProcHandle);

    // 创建full dump
    LPCSTR dumpeFilePath = "D:\\analyze\\PUBG\\TslGame.dmp";
    if (!tool::CreateFullDump(hProcHandle, pid, dumpeFilePath))
    {
        LOG("CreateFullDump failed");
        getchar();
        return -1;
    }

    if (hProcHandle)
    {
        CloseHandle(hProcHandle);
    }

    getchar();

    return 0;
}
