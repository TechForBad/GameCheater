#pragma once

#include "../Common/common.h"

class DriverComm
{
public:
    DriverComm() = default;
    ~DriverComm() = default;

    // 初始化驱动通信
    bool Init();

    // 读进程内存
    bool ReadProcessMemory(IN DWORD pid, IN PBYTE pUserSrc, IN ULONG readLen, OUT PBYTE pUserDst);

    // 写进程内存
    bool WriteProcessMemory(IN PBYTE pUserSrc, IN ULONG writeLen, IN DWORD pid, OUT PBYTE pUserDst);

    // 获取进程模块基地址
    bool GetProcessModuleBase(IN DWORD pid, IN LPCWSTR moduleName, OUT PVOID* pModuleBase, OUT PULONG moduleSize);

    // 创建APC
    bool CreateAPC(IN DWORD tid, IN PVOID addrToExe);

    // 为进程分配内存
    bool AllocProcessMem(IN DWORD pid, IN SIZE_T memSize, IN ULONG allocationType, IN ULONG protect, OUT PVOID* pModuleBase);

private:
    bool LoadDriver(bool normalLoad);

    bool BuildDriverComm();

    bool TestDriverComm();

private:
    bool is_init_{ false };

    using Func_NtQueryIntervalProfile = NTSTATUS(__fastcall*)(IN ULONG ulCode, OUT PULONG ret);
    Func_NtQueryIntervalProfile func_NtQueryIntervalProfile_{ nullptr };

    COMM::CMSG cmsg_{};
};
