#pragma once

#include "imports.h"

namespace mem
{

PVOID GetSystemModuleBase(const char* moduleName, PULONG moduleSize);

PVOID GetSystemBaseModuleExport(const char* moduleName, LPCSTR routineName);

bool WriteMemory(void* address, void* buffer, size_t size);

bool WriteToReadOnlyMemory(void* address, void* buffer, size_t size);

bool Hook(void* destination);

ULONG64 GetModuleBaseFor64BitProcess(PEPROCESS proc, UNICODE_STRING moduleName);

NTSTATUS FindProcessByName(CHAR* processName, PEPROCESS* proc);

}
