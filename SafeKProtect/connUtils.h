#pragma once

#include "common.h"

using FuncConnectionCallback = ULONG(*)(ULONG ulCode);

class ConnUtils
{
public:
    // 初始化连接
    static BOOL InitConnection(FuncConnectionCallback connectionCallback);
};
