#pragma once

#include "common.h"

class MemoryUtils
{
private:

public:
    static PVOID GetModuleBaseFor64BitProcess(PEPROCESS proc, PCWSTR moduleName);
};
