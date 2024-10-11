#pragma once

#include "common.h"

class OperDispatcher
{
public:
    static NTSTATUS DispatchOper(IN OUT COMM::PCMSG pMsg);

private:
    static NTSTATUS ReadProcessMemory(IN DWORD pid, IN PBYTE pUserSrc, IN ULONG readLen, OUT PBYTE pUserDst);

    static NTSTATUS WriteProcessMemory(IN PBYTE pUserSrc, IN ULONG writeLen, IN DWORD pid, OUT PBYTE pUserDst);

    static NTSTATUS GetProcessModuleBase(IN DWORD pid, IN LPCWSTR moduleName, OUT PVOID* pModuleBase, OUT PULONG moduleSize);

    static NTSTATUS CreateRemoteAPC(IN DWORD tid, IN PVOID addrToExe);

    static NTSTATUS AllocProcessMem(IN DWORD pid, IN SIZE_T memSize, IN ULONG allocationType, IN ULONG protect, OUT PVOID* pModuleBase);

    static NTSTATUS FreeProcessMem(IN DWORD pid, IN PVOID moduleBase);

    // 挂起线程
    static NTSTATUS SuspendTargetThread(IN DWORD tid);

    // 恢复线程
    static NTSTATUS ResumeTargetThread(IN DWORD tid);

    // 挂起进程
    static NTSTATUS SuspendTargetProcess(IN DWORD pid);

    // 恢复进程
    static NTSTATUS ResumeTargetProcess(IN DWORD pid);

    // 打开进程
    static NTSTATUS GetHandleForProcessID(IN DWORD pid, OUT PHANDLE pProcHandle);

    // 读物理地址
    static NTSTATUS ReadPhysicalMemory(IN PBYTE pPhySrc, IN ULONG readLen, IN PVOID pUserDst);

    // 写物理地址
    static NTSTATUS WritePhysicalMemory(IN PBYTE pUserSrc, IN ULONG writeLen, IN PVOID pPhyDst);

    // 获取虚拟地址对应的物理地址
    static NTSTATUS GetPhysicalAddress(IN DWORD pid, PVOID virtualAddress, IN PVOID* pPhysicalAddress);
};
