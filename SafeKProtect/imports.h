#pragma once

#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include <intrin.h>

typedef struct PiDDBCacheEntry
{
    LIST_ENTRY		List;
    UNICODE_STRING	DriverName;
    ULONG			TimeDateStamp;
    NTSTATUS		LoadStatus;
    char			_0x0028[16];
}PIDCacheobj;

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation,                // 0   
    SystemProcessorInformation,            // 1   
    SystemPerformanceInformation,          // 2  
    SystemTimeOfDayInformation,            // 3  
    SystemNotImplemented1,                 // 4  
    SystemProcessesAndThreadsInformation,  // 5  
    SystemCallCounts,                      // 6  
    SystemConfigurationInformation,        // 7  
    SystemProcessorTimes,                  // 8  
    SystemGlobalFlag,                      // 9  
    SystemNotImplemented2,                 // 10  
    SystemModuleInformation,               // 11  
    SystemLockInformation,                 // 12  
    SystemNotImplemented3,                 // 13  
    SystemNotImplemented4,                 // 14  
    SystemNotImplemented5,                 // 15  
    SystemHandleInformation,               // 16  
    SystemObjectInformation,               // 17  
    SystemPagefileInformation,             // 18  
    SystemInstructionEmulationCounts,      // 19  
    SystemInvalidInfoClass1,               // 20  
    SystemCacheInformation,                // 21  
    SystemPoolTagInformation,              // 22  
    SystemProcessorStatistics,             // 23  
    SystemDpcInformation,                  // 24  
    SystemNotImplemented6,                 // 25  
    SystemLoadImage,                       // 26  
    SystemUnloadImage,                     // 27  
    SystemTimeAdjustment,                  // 28  
    SystemNotImplemented7,                 // 29  
    SystemNotImplemented8,                 // 30  
    SystemNotImplemented9,                 // 31  
    SystemCrashDumpInformation,            // 32  
    SystemExceptionInformation,            // 33  
    SystemCrashDumpStateInformation,       // 34  
    SystemKernelDebuggerInformation,       // 35  
    SystemContextSwitchInformation,        // 36  
    SystemRegistryQuotaInformation,        // 37  
    SystemLoadAndCallImage,                // 38  
    SystemPrioritySeparation,              // 39  
    SystemNotImplemented10,                // 40  
    SystemNotImplemented11,                // 41  
    SystemInvalidInfoClass2,               // 42  
    SystemInvalidInfoClass3,               // 43  
    SystemTimeZoneInformation,             // 44  
    SystemLookasideInformation,            // 45  
    SystemSetTimeSlipEvent,                // 46  
    SystemCreateSession,                   // 47  
    SystemDeleteSession,                   // 48  
    SystemInvalidInfoClass4,               // 49  
    SystemRangeStartInformation,           // 50  
    SystemVerifierInformation,             // 51  
    SystemAddVerifier,                     // 52  
    SystemSessionProcessesInformation      // 53  
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_THREAD_INFO
{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFO, * PSYSTEM_THREAD_INFO;

typedef struct _SYSTEM_PROCESS_INFO
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SYSTEM_THREAD_INFO Threads[1];
} SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;

typedef struct _RTL_PROCESS_MODULE_INFO
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFO, * PRTL_PROCESS_MODULE_INFO;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFO Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY ModuleListLoadOrder;
    LIST_ENTRY ModuleListMemoryOrder;
    LIST_ENTRY ModuleListInitOrder;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    BYTE Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef void(__stdcall* PPS_POST_PROCESS_INIT_ROUTINE)(void);

typedef struct _PEB
{
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID Reserved4[3];
    PVOID AtlThunkSListPtr;
    PVOID Reserved5;
    ULONG Reserved6;
    PVOID Reserved7;
    ULONG Reserved8;
    ULONG AtlThunkSListPtr32;
    PVOID Reserved9[45];
    BYTE Reserved10[96];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE Reserved11[128];
    PVOID Reserved12[1];
    ULONG SessionId;
} PEB, * PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    PVOID SectionPointer;
    ULONG CheckSum;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef
_Function_class_(KNORMAL_ROUTINE)
_IRQL_requires_max_(PASSIVE_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
KNORMAL_ROUTINE(
    _In_opt_ PVOID NormalContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
);
typedef KNORMAL_ROUTINE* PKNORMAL_ROUTINE;

typedef
_Function_class_(KKERNEL_ROUTINE)
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(APC_LEVEL)
_IRQL_requires_(APC_LEVEL)
_IRQL_requires_same_
VOID
KKERNEL_ROUTINE(
    _In_ struct _KAPC* Apc,
    _Inout_ PKNORMAL_ROUTINE* NormalRoutine,
    _Inout_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2
);
typedef KKERNEL_ROUTINE* PKKERNEL_ROUTINE;

typedef
_Function_class_(KRUNDOWN_ROUTINE)
_IRQL_requires_max_(PASSIVE_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
KRUNDOWN_ROUTINE(
    _In_ struct _KAPC* Apc
);
typedef KRUNDOWN_ROUTINE* PKRUNDOWN_ROUTINE;

typedef enum _KAPC_ENVIRONMENT
{
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT;

typedef struct _MEMORY_STRUCT
{
    BYTE type;
    LONG usermode_pid;
    LONG target_pid;
    ULONG64 base_address;
    void* address;
    LONG size;
    void* output;
    ULONG magic;
}MEMORY_STRUCT;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY
{
    ULONG Unknow1;
    ULONG Unknow2;

#ifdef _AMD64_
    ULONG Unknow3;
    ULONG Unknow4;
#endif

    PVOID Base;
    ULONG Size;
    ULONG Flags;
    USHORT Index;
    USHORT NameLength;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    char ImageName[256];
}SYSTEM_MODULE_INFORMATION_ENTRY, * PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
    ULONG Count;//内核中以加载的模块的个数
    SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
}SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE
{
    PULONG_PTR ServiceTableBase;
    PULONG ServiceCounterTableBase;
    ULONG_PTR NumberOfServices;
    PUCHAR ParamTableBase;
} SYSTEM_SERVICE_DESCRIPTOR_TABLE, * PSYSTEM_SERVICE_DESCRIPTOR_TABLE;

typedef enum _MINIDUMP_TYPE
{
    MiniDumpNormal = 0x00000000,
    MiniDumpWithDataSegs = 0x00000001,
    MiniDumpWithFullMemory = 0x00000002,
    MiniDumpWithHandleData = 0x00000004,
    MiniDumpFilterMemory = 0x00000008,
    MiniDumpScanMemory = 0x00000010,
    MiniDumpWithUnloadedModules = 0x00000020,
    MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
    MiniDumpFilterModulePaths = 0x00000080,
    MiniDumpWithProcessThreadData = 0x00000100,
    MiniDumpWithPrivateReadWriteMemory = 0x00000200,
    MiniDumpWithoutOptionalData = 0x00000400,
    MiniDumpWithFullMemoryInfo = 0x00000800,
    MiniDumpWithThreadInfo = 0x00001000,
    MiniDumpWithCodeSegs = 0x00002000,
    MiniDumpWithoutAuxiliaryState = 0x00004000,
    MiniDumpWithFullAuxiliaryState = 0x00008000,
    MiniDumpWithPrivateWriteCopyMemory = 0x00010000,
    MiniDumpIgnoreInaccessibleMemory = 0x00020000,
    MiniDumpWithTokenInformation = 0x00040000,
    MiniDumpWithModuleHeaders = 0x00080000,
    MiniDumpFilterTriage = 0x00100000,
    MiniDumpWithAvxXStateContext = 0x00200000,
    MiniDumpWithIptTrace = 0x00400000,
    MiniDumpScanInaccessiblePartialPages = 0x00800000,
    MiniDumpFilterWriteCombinedMemory = 0x01000000,
    MiniDumpValidTypeFlags = 0x01ffffff,
} MINIDUMP_TYPE;

typedef struct _KSTACK_CONTROL
{
    ULONGLONG StackBase;                                                    //0x0
    union
    {
        ULONGLONG ActualLimit;                                              //0x8
        ULONGLONG StackExpansion : 1;                                         //0x8
    };
    struct
    {
        ULONGLONG StackBase;                                                    //0x10
        ULONGLONG StackLimit;                                                   //0x18
        ULONGLONG KernelStack;                                                  //0x20
        ULONGLONG InitialStack;                                                 //0x28
        ULONGLONG KernelShadowStackBase;                                        //0x30
        ULONGLONG KernelShadowStackLimit;										//0x38
        ULONGLONG KernelShadowStack;                                            //0x40
        ULONGLONG KernelShadowStackInitial;                                     //0x48
    } Previous;
}KERNEL_STACK_CONTROL, KSTACK_CONTROL, * PKERNEL_STACK_CONTROL, * PKSTACK_CONTROL;

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY RUNTIME_FUNCTION, * PRUNTIME_FUNCTION;

typedef struct _KNONVOLATILE_CONTEXT_POINTERS
{
    union
    {
        PM128A FloatingContext[16];
        struct
        {
            PM128A Xmm0;
            PM128A Xmm1;
            PM128A Xmm2;
            PM128A Xmm3;
            PM128A Xmm4;
            PM128A Xmm5;
            PM128A Xmm6;
            PM128A Xmm7;
            PM128A Xmm8;
            PM128A Xmm9;
            PM128A Xmm10;
            PM128A Xmm11;
            PM128A Xmm12;
            PM128A Xmm13;
            PM128A Xmm14;
            PM128A Xmm15;
        };
    };

    union
    {
        PULONG64 IntegerContext[16];
        struct
        {
            PULONG64 Rax;
            PULONG64 Rcx;
            PULONG64 Rdx;
            PULONG64 Rbx;
            PULONG64 Rsp;
            PULONG64 Rbp;
            PULONG64 Rsi;
            PULONG64 Rdi;
            PULONG64 R8;
            PULONG64 R9;
            PULONG64 R10;
            PULONG64 R11;
            PULONG64 R12;
            PULONG64 R13;
            PULONG64 R14;
            PULONG64 R15;
        };
    };

} KNONVOLATILE_CONTEXT_POINTERS, * PKNONVOLATILE_CONTEXT_POINTERS;

typedef struct _PEB32
{
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR Spare;
    ULONG Mutant;
    ULONG ImageBaseAddress;
    ULONG/*PPEB_LDR_DATA32*/ Ldr;
    ULONG ProcessParameters;
} PEB32, * PPEB32;

typedef struct _PEB64
{
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR Spare;
    UCHAR Padding0[4];
    ULONG64 Mutant;
    ULONG64 ImageBaseAddress;
    ULONG64/*PPEB_LDR_DATA64*/ Ldr;
    RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
} PEB64, * PPEB64;

typedef struct _PEB_LDR_DATA32
{
    ULONG Length;
    UCHAR Initialized;
    ULONG SsHandle;
    LIST_ENTRY32 InLoadOrderModuleList;
    LIST_ENTRY32 InMemoryOrderModuleList;
    LIST_ENTRY32 InInitializationOrderModuleList;
    ULONG EntryInProgress;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
    LIST_ENTRY32 InLoadOrderLinks;
    LIST_ENTRY32 InMemoryOrderLinks;
    LIST_ENTRY32 InInitializationOrderLinks;
    ULONG DllBase;
    ULONG EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING32 FullDllName;
    UNICODE_STRING32 BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY32 HashLinks;
    ULONG SectionPointer;
    ULONG CheckSum;
    ULONG TimeDateStamp;
    ULONG LoadedImports;
    ULONG EntryPointActivationContext;
    ULONG PatchInformation;
    LIST_ENTRY32 ForwarderLinks;
    LIST_ENTRY32 ServiceTagLinks;
    LIST_ENTRY32 StaticLinks;
    ULONG ContextInformation;
    ULONG OriginalBase;
    LARGE_INTEGER LoadTime;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

typedef struct _PEB_LDR_DATA64
{
    ULONG Length;
    UCHAR Initialized;
    ULONG64 SsHandle;
    LIST_ENTRY64 InLoadOrderModuleList;
    LIST_ENTRY64 InMemoryOrderModuleList;
    LIST_ENTRY64 InInitializationOrderModuleList;
    ULONG64 EntryInProgress;
} PEB_LDR_DATA64, * PPEB_LDR_DATA64;

typedef struct _LDR_DATA_TABLE_ENTRY64
{
    LIST_ENTRY64 InLoadOrderLinks;
    LIST_ENTRY64 InMemoryOrderLinks;
    LIST_ENTRY64 InInitializationOrderLinks;
    ULONG64 DllBase;
    ULONG64 EntryPoint;
    ULONG64 SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY64 HashLinks;
    ULONG64 SectionPointer;
    ULONG64 CheckSum;
    ULONG64 TimeDateStamp;
    ULONG64 LoadedImports;
    ULONG64 EntryPointActivationContext;
    ULONG64 PatchInformation;
    LIST_ENTRY64 ForwarderLinks;
    LIST_ENTRY64 ServiceTagLinks;
    LIST_ENTRY64 StaticLinks;
    ULONG64 ContextInformation;
    ULONG64 OriginalBase;
    LARGE_INTEGER LoadTime;
} LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;

extern "C"
{
    NTKERNELAPI NTSTATUS NTAPI ZwProtectVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PULONG ProtectSize,
        ULONG NewProtect,
        PULONG OldProtect
    );

    NTKERNELAPI PVOID NTAPI RtlFindExportedRoutineByName(_In_ PVOID ImageBase, _In_ PCCH RoutineNam);

    NTKERNELAPI NTSTATUS ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);

    NTKERNELAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);

    NTKERNELAPI NTSTATUS NTAPI MmCopyVirtualMemory(
        PEPROCESS SourceProcess,
        PVOID SourceAddress,
        PEPROCESS TargetProcess,
        PVOID TargetAddress,
        SIZE_T BufferSize,
        KPROCESSOR_MODE PreviousMode,
        PSIZE_T ReturnSize
    );

    NTKERNELAPI NTSTATUS NTAPI ZwQueryInformationProcess(
        IN HANDLE ProcessHandle,
        IN PROCESSINFOCLASS ProcessInformationClass,
        OUT PVOID ProcessInformation,
        IN ULONG ProcessInformationLength,
        OUT PULONG ReturnLength OPTIONAL
    );

    NTKERNELAPI NTSTATUS NTAPI NtQueryIntervalProfile(IN KPROFILE_SOURCE ProfileSource, OUT PULONG Interval);

    NTKERNELAPI BOOLEAN NTAPI KeTestAlertThread(IN KPROCESSOR_MODE AlertMode);

    NTKERNELAPI PVOID NTAPI PsGetThreadTeb(IN PETHREAD Thread);

    NTKERNELAPI HWINEVENTHOOK NtUserSetWinEventHook(
        IN DWORD           eventMin,
        IN DWORD           eventMax,
        IN HMODULE         hmodWinEventProc,
        IN PUNICODE_STRING pstrLib OPTIONAL,
        IN PVOID           pfnWinEventProc,
        IN DWORD           idEventProcess,
        IN DWORD           idEventThread,
        IN DWORD           dwFlags
    );

    NTKERNELAPI PPEB64 PsGetProcessPeb(
        _In_ PEPROCESS Process
    );

    NTKERNELAPI PPEB32 PsGetProcessWow64Process(
        _In_ PEPROCESS  Process
    );

    PRUNTIME_FUNCTION NTAPI RtlLookupFunctionEntry(
        _In_ DWORD64 ControlPc,
        _Out_ PDWORD64 ImageBase,
        _Inout_opt_ PVOID HistoryTable
    );

    PEXCEPTION_ROUTINE NTAPI RtlVirtualUnwind(
        _In_ DWORD HandlerType,
        _In_ DWORD64 ImageBase,
        _In_ DWORD64 ControlPc,
        _In_ PRUNTIME_FUNCTION FunctionEntry,
        _Inout_ PCONTEXT ContextRecord,
        _Out_ PVOID* HandlerData,
        _Out_ PDWORD64 EstablisherFrame,
        _Inout_opt_ PKNONVOLATILE_CONTEXT_POINTERS ContextPointers
    );

    NTSTATUS KeUserModeCallback(
        IN ULONG ApiNumber,
        IN PVOID InputBuffer,
        IN ULONG InputLength,
        OUT PVOID* OutputBuffer,
        IN PULONG OutputLength
    );

    NTKERNELAPI
        _IRQL_requires_same_
        _When_(Environment != OriginalApcEnvironment,
               __drv_reportError("Caution: "
                                 "Using an APC environment other than the original environment can lead to "
                                 "a system bugcheck if the target thread is attached to a process with APCs "
                                 "disabled. APC environments should be used with care."))
        VOID
        KeInitializeApc(
            _Out_ PRKAPC Apc,
            _In_ PRKTHREAD Thread,
            _In_ KAPC_ENVIRONMENT Environment,
            _In_ PKKERNEL_ROUTINE KernelRoutine,
            _In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
            _In_opt_ PKNORMAL_ROUTINE NormalRoutine,
            _In_opt_ KPROCESSOR_MODE ProcessorMode,
            _In_opt_ PVOID NormalContext
        );

    NTKERNELAPI
        _Must_inspect_result_
        _IRQL_requires_max_(DISPATCH_LEVEL)
        _IRQL_requires_min_(PASSIVE_LEVEL)
        _IRQL_requires_same_
        BOOLEAN
        KeInsertQueueApc(
            _Inout_ PRKAPC Apc,
            _In_opt_ PVOID SystemArgument1,
            _In_opt_ PVOID SystemArgument2,
            _In_ KPRIORITY Increment
        );
}
