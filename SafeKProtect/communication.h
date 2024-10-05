#pragma once

namespace COMM
{

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
    // 读内存
    Oper_MemoryRead,
    // 写内存
    Oper_MemoryWrite,
    Oper_ModuleBase,
};

#pragma pack(1)
typedef struct _MSG
{
    // 操作类型
    Operation oper;

    // 操作结果，为0则成功，为其他值则失败
    LONG operResult;

    // 是否需要输出
    BOOL needOutput;

    union
    {
        struct Input_MemoryRead
        {
            DWORD pid;
            PBYTE pUserSrc;
            ULONG readLen;

            PBYTE pUserDst;
        } input_MemoryRead;

        struct Input_MemoryWrite
        {
            PBYTE pUserSrc;
            ULONG writeLen;

            DWORD pid;
            PBYTE pUserDst;
        } input_MemoryWrite;
    };
} MSG, * PMSG;
#pragma pack()

}
