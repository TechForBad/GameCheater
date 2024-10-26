#pragma once

#include "common.h"

class VmUtils
{
public:
    static NTSTATUS InitVm();

    static VOID UnInitVm();

private:
    static BOOL DriverpIsSuppoetedOS();
};
