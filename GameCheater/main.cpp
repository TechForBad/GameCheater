#include <windows.h>  
#include <stdio.h>

#include "../Common/common.h"
#include "DriverComm.h"

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
    DriverComm driverComm;
    if (!driverComm.Init())
    {
        LOG("Init failed");
        return -1;
    }

    // 获取进程号为512的模块sxs.dll的基地址和大小
    PVOID pModuleBase = NULL;
    ULONG moduleSize = 0;
    if (!driverComm.GetProcessModuleBase(512, L"sxs.dll", &pModuleBase, &moduleSize))
    {
        LOG("GetProcessModuleBase failed");
        return -1;
    }
    LOG("moduleBase: 0x%llx, moduleSize: 0x%x", pModuleBase, moduleSize);

    // 读进程内存
    PBYTE pUserDst = (PBYTE)malloc(moduleSize);
    if (NULL == pUserDst)
    {
        LOG("malloc failed");
        return -1;
    }
    ZeroMemory(pUserDst, moduleSize);
    if (!driverComm.ReadProcessMemory(512, (PBYTE)pModuleBase, moduleSize, pUserDst))
    {
        LOG("ReadProcessMemory failed");
        return -1;
    }

    return 0;
}
