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
};
