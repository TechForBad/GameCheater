#pragma once

namespace COMM
{

//模块名长度最大值
#define MAX_MODULE_NAME 100

constexpr unsigned long MIN_CODE = 0xFFFF;

constexpr unsigned long TEST_CODE = 0xDEADBEEF;

constexpr unsigned long CTRL_CODE = 0xDEADAEAD;

constexpr unsigned long MSG_PART_PREFIX = 0xADD00000i32;
constexpr unsigned long MSG_PART_1 = MSG_PART_PREFIX | 0x10000i32;
constexpr unsigned long MSG_PART_2 = MSG_PART_PREFIX | 0x20000i32;
constexpr unsigned long MSG_PART_3 = MSG_PART_PREFIX | 0x30000i32;
constexpr unsigned long MSG_PART_4 = MSG_PART_PREFIX | 0x40000i32;

enum Operation : unsigned long
{
    // 读进程内存
    Oper_ProcessMemoryRead,
    // 写进程内存
    Oper_ProcessMemoryWrite,
    // 获取进程模块基地址
    Oper_ProcessModuleBase,
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
    };
} CMSG, * PCMSG;
#pragma pack()

}
