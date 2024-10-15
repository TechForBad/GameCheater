#pragma once

#include "common.h"

class SetCtxCall
{
public:
    VOID SetCtxApcCallback(
        PRKAPC Apc,
        PKNORMAL_ROUTINE* NormalRoutine,
        PVOID* NormalContext,
        PVOID* SystemArgument1,
        PVOID* SystemArgument2
    );

private:
    ULONG64 SANITIZE_VA(
        IN ULONG64 VirtualAddress,
        IN USHORT Segment,
        IN KPROCESSOR_MODE PreviousMode
    );

    VOID PspGetContext(
        IN PKTRAP_FRAME TrapFrame,
        IN PKNONVOLATILE_CONTEXT_POINTERS ContextPointers,
        IN OUT PCONTEXT ContextRecord
    );

    VOID PspSetContext(
        OUT PKTRAP_FRAME TrapFrame,
        OUT PKNONVOLATILE_CONTEXT_POINTERS ContextPointers,
        IN PCONTEXT ContextRecord,
        KPROCESSOR_MODE PreviousMode
    );

    PKTRAP_FRAME PspGetBaseTrapFrame(PETHREAD Thread);
};
