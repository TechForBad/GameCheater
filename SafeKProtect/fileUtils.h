#pragma once

#include "common.h"

class FileUtils
{
public:
    static NTSTATUS LoadFile(PUNICODE_STRING filename, PVOID* buffer, DWORD* size);
};
