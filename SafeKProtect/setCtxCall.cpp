#include "setCtxCall.h"

// 0x6461654469706950ui64
#define PIPI_IDENTIFIYER (((ULONG64)'daeD' << 32) + 'ipiP')

#define PIPI_CALL_IDENTIFIYER (((ULONG64)'llaC' << 32) + 'ipiP')

#define EFLAGS_IF_MASK 0x00000200       // interrupt flag
#define CONTEXT_EXCEPTION_FLAGS (CONTEXT_EXCEPTION_ACTIVE | CONTEXT_SERVICE_ACTIVE)
#define DR7_LEGAL 0xffff0355
#define DR7_ACTIVE 0x0355
#define DR7_TRACE_BRANCH 0x200
#define DR7_LAST_BRANCH 0x100
#define KGDT64_NULL (0 * 16)            // NULL descriptor
#define KGDT64_R0_CODE (1 * 16)         // kernel mode 64-bit code
#define KGDT64_R0_DATA (1 * 16) + 8     // kernel mode 64-bit data (stack)
#define KGDT64_R3_CMCODE (2 * 16)       // user mode 32-bit code
#define KGDT64_R3_DATA (2 * 16) + 8     // user mode 32-bit data
#define KGDT64_R3_CODE (3 * 16)         // user mode 64-bit code
#define KGDT64_SYS_TSS (4 * 16)         // kernel mode system task state
#define KGDT64_R3_CMTEB (5 * 16)        // user mode 32-bit TEB
#define KGDT64_R0_CMCODE (6 * 16)       // kernel mode 32-bit code
#define KGDT64_LAST (7 * 16)            // last entry
#define RPL_MASK 3
#define KiMxCsrMask 0xFFBF
#define KTRAP_FRAME_LENGTH sizeof(KTRAP_FRAME)
#define UNW_FLAG_NHANDLER 0x0
#define UNW_FLAG_EHANDLER 0x1
#define UNW_FLAG_UHANDLER 0x2
#define UNW_FLAG_CHAININFO 0x4
#define SANITIZE_DR7(Dr7, mode) ((Dr7) & DR7_LEGAL)
#define SANITIZE_DRADDR(DrReg, mode)                                         \
    ((mode) == KernelMode ?                                                  \
        (DrReg) :                                                            \
        (((PVOID)(DrReg) <= MM_HIGHEST_USER_ADDRESS) ? (DrReg) : 0))

#define SANITIZE_MXCSR(_mxcsr_) ((_mxcsr_) & KiMxCsrMask)

#define SANITIZE_FCW(_fcw_) ((_fcw_) & 0x1f3f)

#define EFLAGS_SANITIZE 0x00210fd5L

#define SANITIZE_EFLAGS(eFlags, mode) (                                      \
    ((mode) == KernelMode ?                                                  \
        ((eFlags) & EFLAGS_SANITIZE) :                                       \
        (((eFlags) & EFLAGS_SANITIZE) | EFLAGS_IF_MASK)))

#define SIGN_EXTEND_BIT(_va_, _bit_) \
    (ULONG64)(((LONG64)(_va_) << (64 - (_bit_))) >> (64 - (_bit_)))

SetCtxCallTask::SetCtxCallTask(PSET_CONTEXT_CALL_INFO callInfo)
{

    callInfo_ = callInfo;

}

NTSTATUS SetCtxCallTask::Call()
{
    PKAPC kernelModeApc = (PKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), MEM_TAG);
    if (NULL == kernelModeApc)
    {
        LOG_ERROR("ExAllocatePoolWithTag failed");
        return STATUS_UNSUCCESSFUL;
    }

    KeInitializeApc(kernelModeApc, callInfo_->pTargetEthread, OriginalApcEnvironment, SetCtxApcCallback, NULL, NULL, KernelMode, NULL);

    if (!KeInsertQueueApc(kernelModeApc, this, 0, 2))
    {
        LOG_ERROR("KeInsertQueueApc failed");
        ExFreePoolWithTag(kernelModeApc, MEM_TAG);
        return STATUS_NOT_CAPABLE;
    }

    NTSTATUS ntStatus = KeWaitForSingleObject(&callInfo_->kEvent, Executive, KernelMode, FALSE, NULL);
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("KeWaitForSingleObject failed, ntStatus: 0x%x", ntStatus);
        return ntStatus;
    }

    return STATUS_SUCCESS;
}

VOID SetCtxCallTask::SetCtxApcCallback(
    PRKAPC Apc,
    PKNORMAL_ROUTINE* NormalRoutine,
    PVOID* NormalContext,
    PVOID* SystemArgument1,
    PVOID* SystemArgument2
)
{
    ExFreePoolWithTag(Apc, MEM_TAG);

    auto CurrentThread = KeGetCurrentThread();
    if (PsGetTrapFrame(CurrentThread) != 0)
    {
        // apc comes from a interrupt
        DbgBreakPoint();
        // return;
    }

    auto BaseTrapFrame = PspGetBaseTrapFrame(CurrentThread);
    if (NULL == BaseTrapFrame)
    {
        DbgBreakPoint();
        return;
    }

    CONTEXT ContextRecord;
    RtlCaptureContext(&ContextRecord);

    ULONG64 ControlPc;
    ULONG64 ImageBase;
    PRUNTIME_FUNCTION FunctionEntry;
    PVOID HandlerData;
    ULONG64 EstablisherFrame = 0;

    KNONVOLATILE_CONTEXT_POINTERS ContextPointers{};
    ContextPointers.Rbx = &ContextRecord.Rbx;
    ContextPointers.Rsp = &ContextRecord.Rsp;
    ContextPointers.Rbp = &ContextRecord.Rbp;
    ContextPointers.Rsi = &ContextRecord.Rsi;
    ContextPointers.Rdi = &ContextRecord.Rdi;
    ContextPointers.R12 = &ContextRecord.R12;
    ContextPointers.R13 = &ContextRecord.R13;
    ContextPointers.R14 = &ContextRecord.R14;
    ContextPointers.R15 = &ContextRecord.R15;

    ContextPointers.Xmm6 = &ContextRecord.Xmm6;
    ContextPointers.Xmm7 = &ContextRecord.Xmm7;
    ContextPointers.Xmm8 = &ContextRecord.Xmm8;
    ContextPointers.Xmm9 = &ContextRecord.Xmm9;
    ContextPointers.Xmm10 = &ContextRecord.Xmm10;
    ContextPointers.Xmm11 = &ContextRecord.Xmm11;
    ContextPointers.Xmm12 = &ContextRecord.Xmm12;
    ContextPointers.Xmm13 = &ContextRecord.Xmm13;
    ContextPointers.Xmm14 = &ContextRecord.Xmm14;
    ContextPointers.Xmm15 = &ContextRecord.Xmm15;

    do
    {
        ControlPc = ContextRecord.Rip;
        FunctionEntry = RtlLookupFunctionEntry(ControlPc, &ImageBase, NULL);
        if (FunctionEntry)
        {
            RtlVirtualUnwind(
                UNW_FLAG_EHANDLER,
                ImageBase,
                ControlPc,
                FunctionEntry,
                &ContextRecord,
                &HandlerData,
                &EstablisherFrame,
                &ContextPointers
            );
        }
        else
        {
            ContextRecord.Rip = *(PULONG64)(ContextRecord.Rsp);
            ContextRecord.Rsp += 8;
        }
    } while (EstablisherFrame != (ULONG64)BaseTrapFrame);

    CONTEXT OrigContext;
    OrigContext.ContextFlags = CONTEXT_FULL;
    PspGetContext(BaseTrapFrame, &ContextPointers, &OrigContext);

	SetCtxCallTask* thisptr = *(SetCtxCallTask**)SystemArgument1;

    if (!thisptr->bInitCommu)
    {
        PVOID ntdll = GetModuleHandle("ntdll.dll");
        PVOID win32u = GetModuleHandle("win32u.dll");

        // u poi CallRet
        // 00007ffe`88b4a369 xor  edx, edx
        // 00007ffe`88b4a36b lea  rcx, [rsp + 20h]
        // 00007ffe`88b4a370 call ntdll!NtContinue

        thisptr->CallRet = MemoryUtils::FindPatternSect(ntdll, ".text", "E8 ? ? ? ? 33 D2 48 8D 4C 24 20 E8");
		if (!thisptr->CallRet)
		{
			DbgBreakPoint();
		}

		if (RVA(thisptr->CallRet + 12, 5) != (ULONG64)GetProcAddress(ntdll, ("NtContinue")))
		{
			DbgBreakPoint();
		}

        thisptr->CallRet += 5;

        auto instr = (ULONG64)GetProcAddress(MemoryUtils::GetNtModuleBase(NULL), "KeQueryAuxiliaryCounterFrequency") + 4;
        auto bbbb = *(LONG*)(instr + 3);

        auto rva = instr + 7 + bbbb;

        OrigNtQuery = *(ULONG64*)rva;
        *(ULONG64*)rva = (ULONG64)HkCommunicate;

        thisptr->CommuFunction = (ULONG64)GetProcAddress(ntdll, "NtQueryAuxiliaryCounterFrequency"); //your win32k io function or data ptr function;
        thisptr->bInitCommu = true;
    }

    CONTEXT PreCallCtx = OrigContext;
    PreCallCtx.ContextFlags = CONTEXT_CONTROL;
    PreCallCtx.Rsp -= 0x28 + 0x30 + sizeof(CONTEXT) * 2; //alloc stack at the precall to prevent other apc destroy
    // the stack
    PreCallCtx.Rip = (ULONG64)thisptr->CallRet;

    // used in ntcontinue.
    CONTEXT CallDriverCtx = OrigContext;
    CallDriverCtx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    CallDriverCtx.Rsp -= 0x30 + sizeof(CONTEXT);
    CallDriverCtx.Rip = (ULONG64)thisptr->CommuFunction;
    CallDriverCtx.Rcx = CallDriverCtx.Rsp + 0x18;
    CallDriverCtx.Rdx = 0;
    CallDriverCtx.R8 = 0;
    CallDriverCtx.R9 = 0;
    *(ULONG64*)(CallDriverCtx.Rsp + 8) = PIPI_CALL_IDENTIFIYER;
    *(ULONG64*)(CallDriverCtx.Rsp + 0x10) = (ULONG64)thisptr; // using a handle can be more secure. 

    memcpy((PVOID)(CallDriverCtx.Rsp + 0x28), &OrigContext, sizeof(CONTEXT));
    *(PVOID*)(CallDriverCtx.Rsp) = thisptr->CallRet;

    memcpy((PVOID)(PreCallCtx.Rsp + 0x20), &CallDriverCtx, sizeof(CONTEXT));

    PspSetContext(BaseTrapFrame, &ContextPointers, &PreCallCtx, UserMode);
}

PKTRAP_FRAME SetCtxCallTask::PspGetBaseTrapFrame(PETHREAD Thread)
{
    ULONG64 InitialStack;
    PKERNEL_STACK_CONTROL StackControl;

    InitialStack = *(ULONG64*)((ULONG64)Thread + 0x28);
    StackControl = (PKERNEL_STACK_CONTROL)InitialStack;
    while (StackControl->StackExpansion)
    {
        InitialStack = StackControl->Previous.InitialStack;
        StackControl = (PKERNEL_STACK_CONTROL)InitialStack;
    }

    return (PKTRAP_FRAME)(InitialStack - KTRAP_FRAME_LENGTH);
}

ULONG64 SetCtxCallTask::SANITIZE_VA(
	IN ULONG64 VirtualAddress,
	IN USHORT Segment,
	IN KPROCESSOR_MODE PreviousMode
)

/*++

Routine Description:

	This routine canonicalizes a 64-bit virtual address according to the
	supplied segment selector.

Arguments:

	VirtualAddress - Supplies the 64-bit virtual address to canonicalize.

	Segment - Supplies the selector for for the virtual address.

	PreviousMode - Supplies the processor mode for which the exception and
		trap frames are being built.

Return Value:

	Returns the canonicalized virtual address.

--*/

{

	ULONG64 Va;

	if (PreviousMode == UserMode)
	{

		//
		// Zero-extend 32-bit addresses, sign extend bit 48 of 64-bit
		// addresses.
		// 

		if ((Segment == (KGDT64_R3_CMCODE | RPL_MASK)) ||
			(Segment == (KGDT64_R3_DATA | RPL_MASK)))
		{

			Va = (ULONG)VirtualAddress;

		}
		else
		{
			Va = SIGN_EXTEND_BIT(VirtualAddress, 48);
		}

	}
	else
	{
		Va = VirtualAddress;
	}

	return Va;
}

VOID SetCtxCallTask::PspGetContext(
	IN PKTRAP_FRAME TrapFrame,
	IN PKNONVOLATILE_CONTEXT_POINTERS ContextPointers,
	IN OUT PCONTEXT ContextRecord
)

/*++

Routine Description:

	This function selectively moves the contents of the specified trap frame
	and nonvolatile context to the specified context record.

Arguments:

	TrapFrame - Supplies the contents of a trap frame.

	ContextPointers - Supplies the address of context pointers record.

	ContextRecord - Supplies the address of a context record.

Return Value:

	None.

--*/

{

	ULONG ContextFlags;

	PAGED_CODE();

	//
	// Get control information if specified.
	//

	ContextFlags = ContextRecord->ContextFlags;
	if ((ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL)
	{

		//
		// Set registers RIP, CS, RSP, SS, and EFlags.
		//

		ContextRecord->Rip = TrapFrame->Rip;
		ContextRecord->SegCs = TrapFrame->SegCs;
		ContextRecord->SegSs = TrapFrame->SegSs;
		ContextRecord->Rsp = TrapFrame->Rsp;
		ContextRecord->EFlags = TrapFrame->EFlags;
	}

	//
	// Get segment register contents if specified.
	//

	if ((ContextFlags & CONTEXT_SEGMENTS) == CONTEXT_SEGMENTS)
	{

		//
		// Set segment registers GS, FS, ES, DS.
		//

		ContextRecord->SegDs = KGDT64_R3_DATA | RPL_MASK;
		ContextRecord->SegEs = KGDT64_R3_DATA | RPL_MASK;
		ContextRecord->SegFs = KGDT64_R3_CMTEB | RPL_MASK;
		ContextRecord->SegGs = KGDT64_R3_DATA | RPL_MASK;
	}

	//
	//  Get integer register contents if specified.
	//

	if ((ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER)
	{

		//
		// Set integer registers RAX, RCX, RDX, RSI, RDI, R8, R9, R10, RBX,
		// RBP, R11, R12, R13, R14, and R15.
		//

		ContextRecord->Rax = TrapFrame->Rax;
		ContextRecord->Rcx = TrapFrame->Rcx;
		ContextRecord->Rdx = TrapFrame->Rdx;
		ContextRecord->R8 = TrapFrame->R8;
		ContextRecord->R9 = TrapFrame->R9;
		ContextRecord->R10 = TrapFrame->R10;
		ContextRecord->R11 = TrapFrame->R11;

		ContextRecord->Rbx = *ContextPointers->Rbx;
		ContextRecord->Rbp = *ContextPointers->Rbp;
		ContextRecord->Rsi = *ContextPointers->Rsi;
		ContextRecord->Rdi = *ContextPointers->Rdi;
		ContextRecord->R12 = *ContextPointers->R12;
		ContextRecord->R13 = *ContextPointers->R13;
		ContextRecord->R14 = *ContextPointers->R14;
		ContextRecord->R15 = *ContextPointers->R15;
	}

	//
	// Get floating point context if specified.
	//

	if ((ContextFlags & CONTEXT_FLOATING_POINT) == CONTEXT_FLOATING_POINT)
	{

		//
		// Set XMM registers Xmm0-Xmm15 and the XMM CSR contents.
		//
		// N.B. The legacy floating state is handled separately.
		//

		ContextRecord->Xmm0 = TrapFrame->Xmm0;
		ContextRecord->Xmm1 = TrapFrame->Xmm1;
		ContextRecord->Xmm2 = TrapFrame->Xmm2;
		ContextRecord->Xmm3 = TrapFrame->Xmm3;
		ContextRecord->Xmm4 = TrapFrame->Xmm4;
		ContextRecord->Xmm5 = TrapFrame->Xmm5;

		ContextRecord->Xmm6 = *ContextPointers->Xmm6;
		ContextRecord->Xmm7 = *ContextPointers->Xmm7;
		ContextRecord->Xmm8 = *ContextPointers->Xmm8;
		ContextRecord->Xmm9 = *ContextPointers->Xmm9;
		ContextRecord->Xmm10 = *ContextPointers->Xmm10;
		ContextRecord->Xmm11 = *ContextPointers->Xmm11;
		ContextRecord->Xmm12 = *ContextPointers->Xmm12;
		ContextRecord->Xmm13 = *ContextPointers->Xmm13;
		ContextRecord->Xmm14 = *ContextPointers->Xmm14;
		ContextRecord->Xmm15 = *ContextPointers->Xmm15;

		ContextRecord->MxCsr = TrapFrame->MxCsr;
	}

	//
	//
	// Get debug register contents if requested.
	//

	if ((ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS)
	{

		//
		// Set the debug registers DR0, DR1, DR2, DR3, DR6, and DR7.
		//

		if ((TrapFrame->Dr7 & DR7_ACTIVE) != 0)
		{
			ContextRecord->Dr0 = TrapFrame->Dr0;
			ContextRecord->Dr1 = TrapFrame->Dr1;
			ContextRecord->Dr2 = TrapFrame->Dr2;
			ContextRecord->Dr3 = TrapFrame->Dr3;
			ContextRecord->Dr6 = TrapFrame->Dr6;
			ContextRecord->Dr7 = TrapFrame->Dr7;
			if ((TrapFrame->Dr7 & DR7_LAST_BRANCH) != 0)
			{
				ContextRecord->LastBranchToRip = TrapFrame->LastBranchToRip;
				ContextRecord->LastBranchFromRip = TrapFrame->LastBranchFromRip;
				ContextRecord->LastExceptionToRip = TrapFrame->LastExceptionToRip;
				ContextRecord->LastExceptionFromRip = TrapFrame->LastExceptionFromRip;

			}
			else
			{
				ContextRecord->LastBranchToRip = 0;
				ContextRecord->LastBranchFromRip = 0;
				ContextRecord->LastExceptionToRip = 0;
				ContextRecord->LastExceptionFromRip = 0;
			}

		}
		else
		{
			ContextRecord->Dr0 = 0;
			ContextRecord->Dr1 = 0;
			ContextRecord->Dr2 = 0;
			ContextRecord->Dr3 = 0;
			ContextRecord->Dr6 = 0;
			ContextRecord->Dr7 = 0;
			ContextRecord->LastBranchToRip = 0;
			ContextRecord->LastBranchFromRip = 0;
			ContextRecord->LastExceptionToRip = 0;
			ContextRecord->LastExceptionFromRip = 0;
		}
	}

	//
	// Get exception reporting information if requested.
	//

	if ((ContextFlags & CONTEXT_EXCEPTION_REQUEST) != 0)
	{
		ContextRecord->ContextFlags &= ~CONTEXT_EXCEPTION_FLAGS;
		ContextRecord->ContextFlags |= CONTEXT_EXCEPTION_REPORTING;
		if (TrapFrame->ExceptionActive == 1)
		{
			ContextRecord->ContextFlags |= CONTEXT_EXCEPTION_ACTIVE;

		}
		else if (TrapFrame->ExceptionActive == 2)
		{
			ContextRecord->ContextFlags |= CONTEXT_SERVICE_ACTIVE;
		}
	}

	return;
}

VOID SetCtxCallTask::PspSetContext(
	OUT PKTRAP_FRAME TrapFrame,
	OUT PKNONVOLATILE_CONTEXT_POINTERS ContextPointers,
	IN PCONTEXT ContextRecord,
	KPROCESSOR_MODE PreviousMode
)

/*++

Routine Description:

	This function selectively moves the contents of the specified context
	record to the specified trap frame and nonvolatile context.

Arguments:

	TrapFrame - Supplies the address of a trap frame.

	ContextPointers - Supplies the address of a context pointers record.

	ContextRecord - Supplies the address of a context record.

	ProcessorMode - Supplies the processor mode to use when sanitizing
		the PSR and FSR.

Return Value:

	None.

--*/

{

	ULONG ContextFlags;

	PAGED_CODE();

	//
	// Set control information if specified.
	//

	ContextFlags = ContextRecord->ContextFlags;
	if ((ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL)
	{
		TrapFrame->EFlags = SANITIZE_EFLAGS(ContextRecord->EFlags, PreviousMode);
		TrapFrame->Rip = ContextRecord->Rip;
		TrapFrame->Rsp = ContextRecord->Rsp;
	}

	//
	// The segment registers DS, ES, FS, and GS are never restored from saved
	// data. However, SS and CS are restored from the trap frame. Make sure
	// that these segment registers have the proper values.
	//

	if (PreviousMode == UserMode)
	{
		TrapFrame->SegSs = KGDT64_R3_DATA | RPL_MASK;
		if (ContextRecord->SegCs != (KGDT64_R3_CODE | RPL_MASK))
		{
			TrapFrame->SegCs = KGDT64_R3_CMCODE | RPL_MASK;

		}
		else
		{
			TrapFrame->SegCs = KGDT64_R3_CODE | RPL_MASK;
		}

	}
	else
	{
		TrapFrame->SegCs = KGDT64_R0_CODE;
		TrapFrame->SegSs = KGDT64_NULL;
	}

	TrapFrame->Rip = SANITIZE_VA(TrapFrame->Rip, TrapFrame->SegCs, PreviousMode);

	//
	// Set integer registers contents if specified.
	//

	if ((ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER)
	{

		//
		// Set integer registers RAX, RCX, RDX, RSI, RDI, R8, R9, R10, RBX,
		// RBP, R11, R12, R13, R14, and R15.
		//

		TrapFrame->Rax = ContextRecord->Rax;
		TrapFrame->Rcx = ContextRecord->Rcx;
		TrapFrame->Rdx = ContextRecord->Rdx;
		TrapFrame->R8 = ContextRecord->R8;
		TrapFrame->R9 = ContextRecord->R9;
		TrapFrame->R10 = ContextRecord->R10;
		TrapFrame->R11 = ContextRecord->R11;

		*ContextPointers->Rbx = ContextRecord->Rbx;
		*ContextPointers->Rbp = ContextRecord->Rbp;
		*ContextPointers->Rsi = ContextRecord->Rsi;
		*ContextPointers->Rdi = ContextRecord->Rdi;
		*ContextPointers->R12 = ContextRecord->R12;
		*ContextPointers->R13 = ContextRecord->R13;
		*ContextPointers->R14 = ContextRecord->R14;
		*ContextPointers->R15 = ContextRecord->R15;
	}

	//
	// Set floating register contents if requested.
	//

	if ((ContextFlags & CONTEXT_FLOATING_POINT) == CONTEXT_FLOATING_POINT)
	{

		//
		// Set XMM registers Xmm0-Xmm15 and the XMM CSR contents.
		//
		// N.B. The legacy floating state is handled separately.
		//

		TrapFrame->Xmm0 = ContextRecord->Xmm0;
		TrapFrame->Xmm1 = ContextRecord->Xmm1;
		TrapFrame->Xmm2 = ContextRecord->Xmm2;
		TrapFrame->Xmm3 = ContextRecord->Xmm3;
		TrapFrame->Xmm4 = ContextRecord->Xmm4;
		TrapFrame->Xmm5 = ContextRecord->Xmm5;

		*ContextPointers->Xmm6 = ContextRecord->Xmm6;
		*ContextPointers->Xmm7 = ContextRecord->Xmm7;
		*ContextPointers->Xmm8 = ContextRecord->Xmm8;
		*ContextPointers->Xmm9 = ContextRecord->Xmm9;
		*ContextPointers->Xmm10 = ContextRecord->Xmm10;
		*ContextPointers->Xmm11 = ContextRecord->Xmm11;
		*ContextPointers->Xmm12 = ContextRecord->Xmm12;
		*ContextPointers->Xmm13 = ContextRecord->Xmm13;
		*ContextPointers->Xmm14 = ContextRecord->Xmm14;
		*ContextPointers->Xmm15 = ContextRecord->Xmm15;

		//
		// Clear all reserved bits in MXCSR.
		//

		TrapFrame->MxCsr = SANITIZE_MXCSR(ContextRecord->MxCsr);

		//
		// Clear all reserved bits in legacy floating state.
		//
		// N.B. The legacy floating state is restored if and only if the
		//      request mode is user.
		//
		// N.B. The current MXCSR value is placed in the legacy floating
		//      state so it will get restored if the legacy state is
		//      restored.
		//

		ContextRecord->FltSave.MxCsr = ReadMxCsr();
		ContextRecord->FltSave.ControlWord =
			SANITIZE_FCW(ContextRecord->FltSave.ControlWord);
	}

	//
	// Set debug register state if specified.
	//

	//if ((ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS) {
	//
	//	//
	//	// Set the debug registers DR0, DR1, DR2, DR3, DR6, and DR7.
	//	//
	//
	//	TrapFrame->Dr0 = SANITIZE_DRADDR(ContextRecord->Dr0, PreviousMode);
	//	TrapFrame->Dr1 = SANITIZE_DRADDR(ContextRecord->Dr1, PreviousMode);
	//	TrapFrame->Dr2 = SANITIZE_DRADDR(ContextRecord->Dr2, PreviousMode);
	//	TrapFrame->Dr3 = SANITIZE_DRADDR(ContextRecord->Dr3, PreviousMode);
	//	TrapFrame->Dr6 = 0;
	//	TrapFrame->Dr7 = SANITIZE_DR7(ContextRecord->Dr7, PreviousMode);
	//	if (PreviousMode != KernelMode) {
	//		KeGetCurrentThread()->Header.DebugActive =
	//			(BOOLEAN)((TrapFrame->Dr7 & DR7_ACTIVE) != 0);
	//	}
	//}

	return;
}

NTSTATUS SetCtxCallTask::HkCommunicate(ULONG64 a1)
{
	DbgBreakPoint();

    do
    {
        auto TrapFrame = PsGetTrapFrame();
        if (!TrapFrame ||
            !IsValid(TrapFrame->Rsp) ||
            (*(ULONG64*)(TrapFrame->Rsp + 8) != PIPI_CALL_IDENTIFIYER))
        {
			DbgBreakPoint();
            break;
        }

        SetCtxCallTask* thisptr = *(SetCtxCallTask**)(TrapFrame->Rsp + 0x10);
        if (!IsValid((ULONG64)thisptr))
        {
			DbgBreakPoint();
            break;
        }

        //tf->Rsp -= 8;
        if (!thisptr->bUserCallInit)
        {
            thisptr->CtxUserCall.Init();
            thisptr->bUserCallInit = true;
        }

        PSET_CONTEXT_CALL_INFO CallInfo = thisptr->callInfo_;

        if (CallInfo->fun_PreCallKernelRoutine)
        {
            CallInfo->fun_PreCallKernelRoutine(thisptr->callInfo_);
        }

        CallInfo->retVal = thisptr->CtxUserCall.Call(
            CallInfo->userFunction,
            CallInfo->param[0].asU64,
            CallInfo->param[1].asU64,
            CallInfo->param[2].asU64,
            CallInfo->param[3].asU64
		);

        if (CallInfo->fun_PostCallKernelRoutine)
        {
            CallInfo->fun_PostCallKernelRoutine(thisptr->callInfo_);
        }

        KeSetEvent(&CallInfo->kEvent, IO_KEYBOARD_INCREMENT, FALSE);

        return STATUS_UNSUCCESSFUL;
    } while (false);

    return ((NTSTATUS(*)(ULONG64 a1))OrigNtQuery)(a1);
}