#pragma once

#include "DBKControl.h"

enum LoadType
{
    LoadByShellcode,            // 当作shellcode来加载驱动，会由当前进程直接运行驱动的入口点代码
    LoadByIoCreateDriver,       // 调用IoCreateDriver加载驱动，会创建驱动对象，并由系统进程运行驱动的入口点代码
};

// 加载自己的未签名驱动
bool DBK_LoadMyDriver(LoadType loadType, const wchar_t* driverFilePath, const wchar_t* driverName);
