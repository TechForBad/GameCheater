#pragma once

#include "common.h"

class MemoryUtils
{
private:
    // 获取64位进程的指定模块基地址
    PVOID GetModuleBaseFor64BitProcess(PEPROCESS Process, WCHAR* moduleName);

    PVOID GetFunctionAddress(PVOID moduleBase, CHAR* functionName);
    NTSTATUS GetSSDTAddress();

public:
    static PVOID GetSSDTFunctionAddress(CHAR* functionName);
};
