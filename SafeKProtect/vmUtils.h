#pragma once

#include "common.h"

class VmUtils
{
public:
    static NTSTATUS InitVm();

    static VOID UnInitVm();

private:
    static PDRIVER_OBJECT GetDriverObject(PCWSTR driverName);

    static BOOL DriverpIsSuppoetedOS();

private:
    static BOOL is_vm_init_;
};
