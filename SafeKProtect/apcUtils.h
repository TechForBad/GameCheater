#pragma once

#include "common.h"

typedef struct _SET_CONTEXT_CALL_INFORMATION SET_CONTEXT_CALL_INFORMATION, * PSET_CONTEXT_CALL_INFORMATION;

using Fun_PreUserCall = void(*)(PSET_CONTEXT_CALL_INFORMATION);
using Fun_PostUserCall = void(*)(PSET_CONTEXT_CALL_INFORMATION);

struct _SET_CONTEXT_CALL_INFORMATION
{
    PETHREAD pTargetEthread;
    PVOID userFunction;
    ULONG64 retVal;

    Fun_PreUserCall fun_PreCallKernelRoutine;
    Fun_PostUserCall fun_PostCallKernelRoutine;

    SIZE_T paramCnt;
    struct
    {
        ULONG64 asU64;
    } param[1];

    KEVENT kEvent;
};

class ApcUtils
{
public:
    static NTSTATUS CreateRemoteAPC(IN PETHREAD pEthread, IN PVOID addrToExe, IN ULONG64 parameter);

    static NTSTATUS RemoteCallBySwitchContext(PSET_CONTEXT_CALL_INFORMATION callInfo);

private:

};
