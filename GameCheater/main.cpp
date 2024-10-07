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
    if (!tool::GetProcessId(L"dwm.exe", &pid))
    {
        LOG("GetProcessId failed");
        return -1;
    }
    LOG("dwm process id: %d", pid);



    return 0;
}
