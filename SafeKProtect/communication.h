#pragma once

namespace COMM
{

// 模块名长度最大值
#define MAX_MODULE_NAME 100

constexpr unsigned long MIN_CODE = 0xFFFF;

constexpr unsigned long TEST_CODE = 0xDEADBEEF;

constexpr unsigned long CTRL_CODE = 0xDEADAEAD;

constexpr unsigned long MSG_PART_PREFIX = 0xADD00000;
constexpr unsigned long MSG_PART_1 = MSG_PART_PREFIX | 0x10000;
constexpr unsigned long MSG_PART_2 = MSG_PART_PREFIX | 0x20000;
constexpr unsigned long MSG_PART_3 = MSG_PART_PREFIX | 0x30000;
constexpr unsigned long MSG_PART_4 = MSG_PART_PREFIX | 0x40000;

enum Operation : unsigned long
{
    // 读进程内存
    Oper_ProcessMemoryRead,
    // 写进程内存
    Oper_ProcessMemoryWrite,
    // 获取进程模块基地址
    Oper_ProcessModuleBase,
    // 创建APC
    Oper_CreateAPC,
    // 为进程分配内存
    Oper_AllocProcessMem,
    // 为进程释放内存
    Oper_FreeProcessMem,
    // 挂起线程
    Oper_SuspendTargetThread,
    // 恢复线程
    Oper_ResumeTargetThread,
    // 挂起进程
    Oper_SuspendTargetProcess,
    // 恢复进程
    Oper_ResumeTargetProcess,
    // 打开进程
    Oper_GetHandleForProcessID,
    // 读物理地址
    Oper_ReadPhysicalMemory,
    // 写物理地址
    Oper_WritePhysicalMemory,
    // 获取虚拟地址对应的物理地址
    Oper_GetPhysicalAddress,

    // 通过创建APC无模块注入dll
    Oper_InjectDllWithNoModuleByAPC,
    // 通过EventHook无模块注入dll
    Oper_InjectDllWithNoModuleByEventHook,

    // 为指定进程创建full dump
    Oper_ProcessCreateFullDump,
};

#pragma pack(1)
typedef struct _CMSG
{
    // 操作类型
    Operation oper;

    // 是否需要输出
    BOOL needOutput{ false };

    union
    {
        // 读进程内存
        struct Input_MemoryRead
        {
            DWORD pid;
            PBYTE pUserSrc;
            ULONG readLen;

            PBYTE pUserDst;
        } input_MemoryRead;

        // 写进程内存
        struct Input_MemoryWrite
        {
            PBYTE pUserSrc;
            ULONG writeLen;

            DWORD pid;
            PBYTE pUserDst;
        } input_MemoryWrite;

        // 获取进程模块基地址
        struct Input_ModuleBase
        {
            DWORD pid;
            WCHAR moduleName[MAX_MODULE_NAME];
        } input_ModuleBase;

        struct Output_ModuleBase
        {
            PVOID moduleBase;
            ULONG moduleSize;
        } output_ModuleBase;

        // 创建APC
        struct Input_CreateAPC
        {
            DWORD tid;
            PVOID addrToExe;
        } input_CreateAPC;

        // 为进程分配内存
        struct Input_AllocProcessMem
        {
            DWORD pid;
            SIZE_T memSize;
            ULONG allocationType;
            ULONG protect;
        } input_AllocProcessMem;

        struct Output_AllocProcessMem
        {
            PVOID moduleBase;
        } output_AllocProcessMem;

        // 为进程释放内存
        struct Input_FreeProcessMem
        {
            DWORD pid;
            PVOID moduleBase;
        } input_FreeProcessMem;

        // 挂起线程
        struct Input_SuspendTargetThread
        {
            DWORD tid;
        } input_SuspendTargetThread;

        // 恢复线程
        struct Input_ResumeTargetThread
        {
            DWORD tid;
        } input_ResumeTargetThread;

        // 挂起进程
        struct Input_SuspendTargetProcess
        {
            DWORD pid;
        } input_SuspendTargetProcess;

        // 恢复进程
        struct Input_ResumeTargetProcess
        {
            DWORD pid;
        } input_ResumeTargetProcess;

        // 打开进程
        struct Input_GetHandleForProcessID
        {
            DWORD pid;
        } input_GetHandleForProcessID;

        struct Output_GetHandleForProcessID
        {
            HANDLE hProcHandle;
        } output_GetHandleForProcessID;

        // 读物理地址
        struct Input_ReadPhysicalMemory
        {
            PBYTE pPhySrc;
            ULONG readLen;

            PVOID pUserDst;
        } input_ReadPhysicalMemory;

        // 写物理地址
        struct Input_WritePhysicalMemory
        {
            PBYTE pUserSrc;
            ULONG writeLen;

            PVOID pPhyDst;
        } input_WritePhysicalMemory;

        // 获取虚拟地址对应的物理地址
        struct Input_GetPhysicalAddress
        {
            DWORD pid;
            PVOID virtualAddress;
        } input_GetPhysicalAddress;

        struct Output_GetPhysicalAddress
        {
            PVOID physicalAddress;
        } output_GetPhysicalAddress;

        // 通过创建APC无模块注入dll
        struct Input_InjectDllWithNoModuleByAPC
        {
            DWORD pid;
            WCHAR dllPath[MAX_PATH];
        } input_InjectDllWithNoModuleByAPC;

        // 通过EventHook无模块注入dll
        struct Input_InjectDllWithNoModuleByEventHook
        {
            DWORD pid;
            WCHAR dllPath[MAX_PATH];
        } input_InjectDllWithNoModuleByEventHook;

        // 为指定进程创建full dump
        struct Input_ProcessCreateFullDump
        {
            DWORD pid;
            WCHAR dumpPath[MAX_PATH];
        } input_ProcessCreateFullDump;
    };
} CMSG, * PCMSG;
#pragma pack()

}
