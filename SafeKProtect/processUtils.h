#pragma once

#include "common.h"

class MemoryUtils
{
private:
    // ��ȡ64λ���̵�ָ��ģ�����ַ
    PVOID GetModuleBaseFor64BitProcess(PEPROCESS Process, WCHAR* moduleName);

    PVOID GetFunctionAddress(PVOID moduleBase, CHAR* functionName);
    NTSTATUS GetSSDTAddress();

public:
    static PVOID GetSSDTFunctionAddress(CHAR* functionName);
};
