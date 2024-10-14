#pragma once

#include "common.h"

class MemoryUtils
{
public:
    // 安全拷贝
    static NTSTATUS SafeCopyMemory_R3_to_R0(ULONG_PTR srcAddr, ULONG_PTR dstAddr, ULONG size);
    static NTSTATUS SafeCopyMemory_R0_to_R3(PVOID srcAddr, PVOID dstAddr, ULONG size);

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

    // 判断地址是否安全
    static BOOLEAN IsAddressSafe(UINT_PTR startAddress);

    // 读物理地址
    static NTSTATUS ReadPhysicalMemory(IN PBYTE pPhySrc, IN ULONG readLen, IN PVOID pUserDst);

    // 写物理地址
    static NTSTATUS WritePhysicalMemory(IN PBYTE pUserSrc, IN ULONG writeLen, IN PVOID pPhyDst);

    // 获取虚拟地址对应的物理地址
    static NTSTATUS GetPhysicalAddress(IN DWORD pid, PVOID virtualAddress, IN PVOID* pPhysicalAddress);
};
