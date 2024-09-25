#pragma once

#include "../Common/public_def.h"

#include "imports.h"
#include "communication.h"
#include "mem.h"
#include "cleaner.h"

// 内存分配标志
#define MEM_TAG 'RICH'

#define Printf(...) DbgPrintEx( DPFLTR_SYSTEM_ID, DPFLTR_ERROR_LEVEL, "[+]" __VA_ARGS__ )

#define ProbeOutputType(pointer, type)                                        \
_Pragma("warning(suppress : 6001)")                                           \
ProbeForWrite(pointer, sizeof(type), TYPE_ALIGNMENT(type))

#define ProbeInputType(pointer, type)                                         \
_Pragma("warning(suppress : 6001)")                                           \
ProbeForRead(pointer, sizeof(type), TYPE_ALIGNMENT(type))

#define ProbeOutputBytes(pointer, size)                                       \
_Pragma("warning(suppress : 6001)")                                           \
ProbeForWrite(pointer, size, TYPE_ALIGNMENT(BYTE))

#define ProbeInputBytes(pointer, size)                                        \
_Pragma("warning(suppress : 6001)")                                           \
ProbeForRead(pointer, size, TYPE_ALIGNMENT(BYTE))

BOOL InitGetProcessNameOffset();

VOID GetProcessName(IN PEPROCESS proc, OUT PCHAR procName);

// 返回系统模块信息指针，需要使用ExFreePool释放该缓存
PSYSTEM_MODULE_INFORMATION GetSystemModuleInformation();

PVOID GetSSDTFunctionAddress(IN CHAR* functionName);
