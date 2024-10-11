#pragma once

#include "common.h"

using FuncIsConnectionCodeCallback = BOOL(*)(ULONG ulCode);

using FuncConnectionCallback = ULONG(*)(ULONG ulCode);

class ConnUtils
{
public:
    // 初始化连接
    static BOOL InitConnection(FuncIsConnectionCodeCallback isConnectionCodeCallback, FuncConnectionCallback connectionCallback);
};
