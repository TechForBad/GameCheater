#include "setCtxCall.h"

typedef struct _CFG_CALL_TARGET_INFO
{
    ULONG_PTR Offset;
    ULONG_PTR Flags;
} CFG_CALL_TARGET_INFO, * PCFG_CALL_TARGET_INFO;

typedef struct _VM_INFORMATION
{
    DWORD NumberOfOffsets;
    DWORD MustBeZero;
    PVOID TargetsProcessed;
    PCFG_CALL_TARGET_INFO CallTargets;
    union _Section
    {
        HANDLE Section;
        DWORD64 Data;
    } Section;
    ULONG64 ExpectedFileOffset;
} VM_INFORMATION, * PVM_INFORMATION;

BOOL UsermodeCallback::Init()
{
    // KiCallUserMode = (KiCallUserModefn)0xfffff801735c4ac0;
    // MmCreateKernelStack = (MmCreateKernelStackfn)0xfffff8017346c210;
    // MmDeleteKernelStack = (MmDeleteKernelStackfn)0xfffff8017346d1e0;

    contextUser_ = (CONTEXT*)UAlloc(sizeof(CONTEXT), PAGE_READWRITE);
    if (NULL == contextUser_)
    {
        LOG_ERROR("UAlloc failed");
        return FALSE;
    }

    ULONG ntdllSize = 0;
    PVOID ntdllBase = GetCurrentProcessModule("ntdll.dll", &ntdllSize);
    if ((NULL == ntdllBase) || (0 == ntdllSize))
    {
        LOG_ERROR("GetCurrentProcessModule failed");
        return FALSE;
    }
    ntContinue_ = GetProcAddress(ntdllBase, "NtContinue");
    if (NULL == ntContinue_)
    {
        LOG_ERROR("GetProcAddress failed");
        return FALSE;
    }

    CFG_CALL_TARGET_INFO targetInfo[1];
    targetInfo[0].Flags = 0x00000001;
    targetInfo[0].Offset = (ULONG_PTR)((ULONG64)ntContinue_ - (ULONG64)ntdllBase);

    MEMORY_RANGE_ENTRY rangeEntry;
    rangeEntry.VirtualAddress = ntdllBase;
    rangeEntry.NumberOfBytes = ntdllSize;

    VM_INFORMATION vmInfo;
    vmInfo.NumberOfOffsets = 1;
    vmInfo.MustBeZero = 0;
    vmInfo.TargetsProcessed = &vmInfo.ExpectedFileOffset;

    vmInfo.CallTargets = &targetInfo[0];
    vmInfo.Section.Section = 0;
    vmInfo.Section.Data = 0;
    vmInfo.ExpectedFileOffset = 0;

    /*
    *  FIX CFG  --

        USER32!_fnDWORD:
        sub     rsp,58h
        mov     rax,rcx
        xor     ecx,ecx
        mov     dword ptr [rsp+38h],ecx
        mov     qword ptr [rsp+40h],rcx
        mov     rdx,qword ptr [rax+20h]
        mov     r9,qword ptr [rax+18h]
        mov     r8,qword ptr [rax+10h]
        mov     rcx,qword ptr [rax]
        mov     qword ptr [rsp+20h],rdx
        mov     edx,dword ptr [rax+8]
        mov     rax,qword ptr [rax+28h]
        call    qword ptr [USER32!_guard_dispatch_icall_fptr (00007ffe`87599b10)]
    */
    NTSTATUS ntStatus = ZwSetInformationVirtualMemory((HANDLE)-1, (VIRTUAL_MEMORY_INFORMATION_CLASS)2, 1, &rangeEntry, (PVOID)&vmInfo, 0x28);

    // __db();
    // MmCreateKernelStack = (pv)(RVA(FindPatternSect(KBase, (".text"), ("E8 ? ? ? ? 41 83 CF 04")), 5));
    // ImpCall(DbgPrintEx, 0, 0, "MmCreateKernelStack %llx\n", MmCreateKernelStack);
    // __db();
    // MmDeleteKernelStack = (pv)(RVA(FindPatternSect(KBase, ("PAGE"), ("8B D5 E8 ? ? ? ? 48 8B 05 ? ? ? ? 48 05 ? ? ? ?")), 7));
    // ImpCall(DbgPrintEx, 0, 0, "MmDeleteKernelStack %llx\n", MmDeleteKernelStack);
    // __db();
    // KiCallUserMode = (pv)(RVA(FindPatternSect(KBase, ("PAGE"), ("4D 8D ? ? 48 8B 94 24 ? ? ? ? 48 8B 8C 24 ? ? ? ? E8 ? ? ? ?")), 25));
    // ImpCall(DbgPrintEx, 0, 0, "KiCallUserMode %llx\n", KiCallUserMode);

    return TRUE;
}

UsermodeCallback::~UsermodeCallback()
{
    if (contextUser_)
    {
        UFree(contextUser_);
        contextUser_ = NULL;
    }
}

NTSTATUS UsermodeCallback::KeUserModeCall(
    IN ULONG ApiNumber,
    IN PVOID   InputBuffer,
    IN ULONG InputLength,
    OUT PVOID* OutputBuffer,
    IN PULONG OutputLength
)
{
    PKTRAP_FRAME TrapFrame;
    ULONG64 OldStack;
    NTSTATUS Status;
    ULONG Length;
    PUCALLOUT_FRAME CalloutFrame;

    auto CurrentThread = __readgsqword(0x188);
    *(UCHAR*)(CurrentThread + 0x2db) = *(UCHAR*)(CurrentThread + 0x2db) + 1; // CallbackNestingLevel++

    DWORD64 StackBase = (DWORD64)fun_MmCreateKernelStack_(FALSE, 0, 0);

    PKSTACK_CONTROL KSC = (PKSTACK_CONTROL)(StackBase - sizeof(KSTACK_CONTROL));
    KSC->StackBase = StackBase;
    KSC->StackLimit = StackBase - KERNEL_STACK_SIZE;
    KSC->PreviousStackBase = *(DWORD64*)((DWORD64)KeGetCurrentThread() + 0x38);//KernelStack
    KSC->PreviousStackLimit = *(DWORD64*)((DWORD64)KeGetCurrentThread() + 0x30);//StackLimit
    KSC->PreviousInitialStack = *(DWORD64*)((DWORD64)KeGetCurrentThread() + 0x28);//InitialStack
    memset(&KSC->ShadowStackControl, 0, 8 * 4);

    TrapFrame = PsGetTrapFrame(KeGetCurrentThread());
    OldStack = TrapFrame->Rsp;

    Length = ((InputLength + STACK_ROUND) & ~STACK_ROUND) + UCALLOUT_FRAME_LENGTH;
    CalloutFrame = (PUCALLOUT_FRAME)((OldStack - Length) & ~STACK_ROUND);
    memmove(&CalloutFrame[1], InputBuffer, InputLength);

    CalloutFrame->Buffer = &CalloutFrame[1];
    CalloutFrame->Length = InputLength;
    CalloutFrame->ApiNumber = ApiNumber;
    CalloutFrame->MachineFrame.Rsp = OldStack;
    CalloutFrame->MachineFrame.Rip = TrapFrame->Rip;

    TrapFrame->Rsp = (ULONG64)CalloutFrame;

    Status = fun_KiCallUserMode_(
        OutputBuffer,
        OutputLength,
        KSC,
        StackBase,
        0,
        0
    );

    *(UCHAR*)(CurrentThread + 0x2db) = *(UCHAR*)(CurrentThread + 0x2db) - 1; // CallbackNestingLevel--

    fun_MmDeleteKernelStack_(StackBase, FALSE);

    TrapFrame->Rsp = OldStack;
    return Status;
}
