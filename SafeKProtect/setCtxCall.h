#pragma once

#include "common.h"

typedef struct _SET_CONTEXT_CALL_INFO SET_CONTEXT_CALL_INFO, * PSET_CONTEXT_CALL_INFO;

// executed on the context of target process, irql = 0. 
using Fun_PreUserCall = void(*)(PSET_CONTEXT_CALL_INFO);
using Fun_PostUserCall = void(*)(PSET_CONTEXT_CALL_INFO);

struct _SET_CONTEXT_CALL_INFO
{
    PETHREAD pTargetEthread;
    PVOID userFunction;
    ULONG64 retVal;
    KEVENT kEvent;

    Fun_PreUserCall fun_PreCallKernelRoutine;
    Fun_PostUserCall fun_PostCallKernelRoutine;

    SIZE_T paramCnt;
    struct
    {
        ULONG64 asU64;
    } param[1];
};

class SetCtxCallTask
{
private:
    PSET_CONTEXT_CALL_INFO callInfo_{ nullptr };

    ULONG64 CommuFunction{ 0 };
    PUCHAR CallRet{ NULL };

    UsermodeCallback CtxUserCall;
    bool bUserCallInit{ FALSE };

    bool bInitCommu{ FALSE };

    static ULONG64 OrigNtQuery;

public:
    SetCtxCallTask(PSET_CONTEXT_CALL_INFO callInfo);

    NTSTATUS Call();

private:
    static ULONG64 SANITIZE_VA(
        IN ULONG64 VirtualAddress,
        IN USHORT Segment,
        IN KPROCESSOR_MODE PreviousMode
    );

    static VOID PspGetContext(
        IN PKTRAP_FRAME TrapFrame,
        IN PKNONVOLATILE_CONTEXT_POINTERS ContextPointers,
        IN OUT PCONTEXT ContextRecord
    );

    static VOID PspSetContext(
        OUT PKTRAP_FRAME TrapFrame,
        OUT PKNONVOLATILE_CONTEXT_POINTERS ContextPointers,
        IN PCONTEXT ContextRecord,
        KPROCESSOR_MODE PreviousMode
    );

    static VOID SetCtxApcCallback(
        PRKAPC Apc,
        PKNORMAL_ROUTINE* NormalRoutine,
        PVOID* NormalContext,
        PVOID* SystemArgument1,
        PVOID* SystemArgument2
    );

    static PKTRAP_FRAME PspGetBaseTrapFrame(PETHREAD Thread);

    static NTSTATUS HkCommunicate(ULONG64 a1);
};
