#pragma once

#define SYSCALL_CODE 0xDEADBEEF

enum operation : int
{
    for_test = 0,
    memory_read,
    memory_write,
    module_base,
};

#pragma pack(1)  // 设置1字节对齐
struct cmd_t
{
    bool success = false;
    unsigned int verification_code = 0;
    operation operation;
    void* buffer;
    ULONG64	address;
    ULONG size;
    ULONG pid;
    const char* module_name;
    ULONG64 base_address;
};
#pragma pack()  // 恢复默认对齐
