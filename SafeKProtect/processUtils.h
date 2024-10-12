#pragma once

#include "common.h"

class ProcessUtils
{
private:
    // 根据EPROCESS和模块名获取模块基地址
    static PVOID GetModuleBaseFor64BitProcess(PEPROCESS proc, PCWSTR moduleName);

public:
    static BOOL Init(PDRIVER_OBJECT driver_object);

    static VOID GetProcessName(IN PEPROCESS proc, OUT PCHAR procName);

    static NTSTATUS FindPidByName(LPCWSTR processName, PULONG pid);

    static NTSTATUS SuspendTargetThread(IN DWORD tid);

    static NTSTATUS ResumeTargetThread(IN DWORD tid);

    static NTSTATUS SuspendTargetProcess(IN DWORD pid);

    static NTSTATUS ResumeTargetProcess(IN DWORD pid);
};

OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info);
OB_PREOP_CALLBACK_STATUS OnPreOpenThread(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info);
