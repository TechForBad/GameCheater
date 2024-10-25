#pragma once

#include "common.h"

class OperDispatcher
{
public:
    static NTSTATUS DispatchOper(IN OUT COMM::PCMSG pMsg);

private:
    // 通过建立MDL映射读进程内存
    static NTSTATUS ReadProcessMemoryByMdl(IN DWORD pid, IN PBYTE pUserSrc, IN ULONG readLen, OUT PBYTE pUserDst);

    // 通过建立MDL映射写进程内存
    static NTSTATUS WriteProcessMemoryByMdl(IN PBYTE pUserSrc, IN ULONG writeLen, IN DWORD pid, OUT PBYTE pUserDst);

    // 通过读物理内存读进程内存
    static NTSTATUS ReadProcessMemoryByPhysical(IN DWORD pid, IN PBYTE pUserSrc, IN ULONG readLen, OUT PBYTE pUserDst);

    // 通过写物理内存写进程内存
    static NTSTATUS WriteProcessMemoryByPhysical(IN PBYTE pUserSrc, IN ULONG writeLen, IN DWORD pid, OUT PBYTE pUserDst);

    // 获取进程模块基地址
    static NTSTATUS GetProcessModuleBase(IN DWORD pid, IN LPCWSTR moduleName, OUT PVOID* pModuleBase, OUT PULONG moduleSize);

    // 创建APC
    static NTSTATUS CreateRemoteAPC(IN DWORD tid, IN PVOID addrToExe, IN ULONG64 parameter);

    // 为进程分配内存
    static NTSTATUS AllocProcessMem(IN DWORD pid, IN SIZE_T memSize, IN ULONG allocationType, IN ULONG protect, OUT PVOID* pModuleBase);

    // 为进程释放内存
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

    // 通过创建APC无模块注入dll
    static NTSTATUS InjectDllWithNoModuleByAPC(IN DWORD pid, IN LPCWSTR dllPath);

    // 通过EventHook无模块注入dll
    static NTSTATUS InjectDllWithNoModuleByEventHook(IN DWORD pid, IN LPCWSTR dllPath);

    // 为指定进程调用MessageBox弹框
    static NTSTATUS ProcessCallMessageBox(IN DWORD pid);

    // 为指定进程调用MiniDumpWriteDump创建full dump
    static NTSTATUS ProcessCallMiniDumpWriteDump(IN DWORD pid, IN LPCWSTR dumpPath);
};
