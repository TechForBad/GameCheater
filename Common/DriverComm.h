#pragma once

#include "common.h"
#include "../SafeKProtect/communication.h"

class DriverComm
{
public:
    static DriverComm* GetInstance()
    {
        static DriverComm instance;
        return &instance;
    }

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

    // 为进程释放内存
    bool FreeProcessMem(IN DWORD pid, IN PVOID moduleBase);

    // 挂起线程
    bool SuspendTargetThread(IN DWORD tid);

    // 恢复线程
    bool ResumeTargetThread(IN DWORD tid);

    // 挂起进程
    bool SuspendTargetProcess(IN DWORD pid);

    // 恢复进程
    bool ResumeTargetProcess(IN DWORD pid);

    // 打开进程
    bool GetHandleForProcessID(IN DWORD pid, OUT PHANDLE pProcHandle);

    // 读物理地址
    bool ReadPhysicalMemory(IN PBYTE pPhySrc, IN ULONG readLen, IN PVOID pUserDst);

    // 写物理地址
    bool WritePhysicalMemory(IN PBYTE pUserSrc, IN ULONG writeLen, IN PVOID pPhyDst);

    // 获取虚拟地址对应的物理地址
    bool GetPhysicalAddress(IN DWORD pid, PVOID virtualAddress, IN PVOID* pPhysicalAddress);

private:
    DriverComm() = default;
    ~DriverComm() = default;
    DriverComm(const DriverComm&) = delete;
    DriverComm& operator=(const DriverComm&) = delete;

private:
    bool LoadDriver(bool normalLoad);
    bool InitDriverComm();
    bool BuildDriverComm();
    bool TestDriverComm();

private:
    bool is_init_{ false };

    using Func_NtQueryIntervalProfile = NTSTATUS(__fastcall*)(IN ULONG ulCode, OUT PULONG ret);
    Func_NtQueryIntervalProfile func_NtQueryIntervalProfile_{ nullptr };

    COMM::CMSG cmsg_{};
};
