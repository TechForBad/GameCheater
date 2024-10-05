#pragma once

#include "common.h"

class OperDispatcher
{
public:
    static NTSTATUS DispatchOper(IN OUT COMM::PMSG pMsg);

private:
    static NTSTATUS ReadProcessMemory(DWORD pid, PBYTE src, ULONG readLen, PBYTE dst);

    static NTSTATUS WriteProcessMemory(PBYTE src, ULONG writeLen, DWORD pid, PBYTE dst);
};
