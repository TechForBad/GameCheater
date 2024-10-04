#pragma once

#include "imports.h"

namespace mem
{

PVOID GetSystemModuleBase(LPCSTR moduleName, PULONG moduleSize);

PVOID GetSystemBaseModuleExport(LPCSTR moduleName, LPCSTR exportName);

bool WriteMemory(void* address, void* buffer, size_t size);

bool WriteToReadOnlyMemory(void* address, void* buffer, size_t size);

bool Hook(void* destination);



NTSTATUS FindProcessByName(CHAR* processName, PEPROCESS* proc);



}
