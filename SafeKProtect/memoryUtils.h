#pragma once

#include "common.h"

class MemoryUtils
{
public:
    static BOOLEAN DataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask);

    static BYTE* FindPattern(BYTE* dwAddress, UINT64 dwLen, const BYTE* bMask, char* szMask);

    // 查询系统信息，返回值需要释放内存
    static PVOID GetSystemInformation(SYSTEM_INFORMATION_CLASS sysInfoClass);

    // 根据模块名获取模块基地址及其大小
    static PVOID GetSystemModuleBase(LPCSTR moduleName, PULONG moduleSize);

    // 根据模块名和导出名获取地址
    static PVOID GetModuleExportAddress(LPCSTR moduleName, LPCSTR exportName);

    // 根据模块基地址和导出名获取地址
    static PVOID GetFunctionAddressFromExportTable(PVOID moduleBase, LPCSTR functionName);

    static ULONG GetFunctionIndexFromExportTable(PVOID pBaseAddress, LPCSTR pszFunctionName);

    // 获取进程模块基地址
    static PVOID GetProcessModuleBase(PEPROCESS proc, PCWSTR moduleName, PULONG moduleSize);

    // 获取NT模块基地址及其大小
    static PVOID GetNtModuleBase(PULONG ntSize);

    // 获取SSDT地址
    static PSYSTEM_SERVICE_DESCRIPTOR_TABLE GetSSDTAddress();

    // 根据函数名获取SSDT函数地址
    static PVOID GetSSDTFunctionAddress(LPCSTR functionName);

    static BOOLEAN IsAddressSafe(UINT_PTR startAddress);
};
