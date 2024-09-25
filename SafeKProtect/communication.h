#pragma once

#define SYSCALL_CODE 0xDEADBEEF

enum Operation : int
{
    for_test = 0,
    memory_read,
    memory_write,
    module_base,
};

#pragma pack(1)
struct COMM_MSG
{
    Operation oper;
    union
    {

    };
};
#pragma pack()
