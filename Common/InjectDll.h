#pragma once

#include "common.h"

class InjectDll
{
public:
    static bool RemoteInjectDll(DWORD pid, LPCWSTR injectedDllPath);
};
