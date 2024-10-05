#pragma once

namespace COMM
{

constexpr unsigned long MIN_CODE = 0xffff;
constexpr unsigned long TEST_CODE = 0xDEADBEEF;

enum Operation : unsigned long
{
    for_test = 0,
    memory_read,
    memory_write,
    module_base,
};

#pragma pack(1)
struct MSG
{
    Operation oper;
    union
    {

    };
};
#pragma pack()

}
