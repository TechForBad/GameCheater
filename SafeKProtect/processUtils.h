#pragma once

#include "common.h"

class ProcessUtils
{
private:
    // 根据EPROCESS和模块名获取模块基地址
    static PVOID GetModuleBaseFor64BitProcess(PEPROCESS proc, PCWSTR moduleName);

public:
    static BOOL Init(PDRIVER_OBJECT driver_object);

    static VOID GetProcessName(PEPROCESS proc, PCHAR procName);

    static NTSTATUS FindPidByName(LPCWSTR processName, PULONG pid);

    static PSYSTEM_PROCESS_INFO FindProcessInformation(PSYSTEM_PROCESS_INFO pSystemProcessInfo, ULONG pid);

    static NTSTATUS SuspendTargetThread(DWORD tid);

    static NTSTATUS ResumeTargetThread(DWORD tid);

    static NTSTATUS SuspendTargetProcess(DWORD pid);

    static NTSTATUS ResumeTargetProcess(DWORD pid);

    // 获取进程的一个可以进行APC注入的线程，调用前需要attach到这个进程，调用后需要释放ETHREAD引用
    static NTSTATUS FindProcessEthread(PEPROCESS pProcess, PETHREAD* ppThread);

private:
    static BOOL SkipThread(PETHREAD pThread);
};

OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info);
OB_PREOP_CALLBACK_STATUS OnPreOpenThread(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info);
