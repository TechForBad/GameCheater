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

    // 通过建立MDL映射读进程内存
    bool ReadProcessMemoryByMdl(IN DWORD pid, IN PBYTE pUserSrc, IN ULONG readLen, OUT PBYTE pUserDst);

    // 通过建立MDL映射写进程内存
    bool WriteProcessMemoryByMdl(IN PBYTE pUserSrc, IN ULONG writeLen, IN DWORD pid, OUT PBYTE pUserDst);

    // 通过读物理内存读进程内存
    bool ReadProcessMemoryByPhysical(IN DWORD pid, IN PBYTE pUserSrc, IN ULONG readLen, OUT PBYTE pUserDst);

    // 通过写物理内存写进程内存
    bool WriteProcessMemoryByPhysical(IN PBYTE pUserSrc, IN ULONG writeLen, IN DWORD pid, OUT PBYTE pUserDst);

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

    // 通过创建APC无模块注入dll
    bool InjectDllWithNoModuleByAPC(IN DWORD pid, IN LPCWSTR dllPath);

    // 通过EventHook无模块注入dll
    bool InjectDllWithNoModuleByEventHook(IN DWORD pid, IN LPCWSTR dllPath);

    // 为指定进程调用MiniDumpWriteDump创建full dump
    bool ProcessCallMiniDumpWriteDump(IN DWORD pid, IN LPCWSTR dumpPath);

    // 初始化Vm
    bool InitVm();

    // 取消Vm
    bool UnInitVm();

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
