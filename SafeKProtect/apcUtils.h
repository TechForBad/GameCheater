#pragma once

#include "common.h"

class ApcUtils
{
public:
    static NTSTATUS CreateRemoteAPC(IN PETHREAD pEthread, IN PVOID addrToExe, IN ULONG64 parameter);

    static NTSTATUS RemoteCallMessageBoxBySetCtx(DWORD pid);
};
