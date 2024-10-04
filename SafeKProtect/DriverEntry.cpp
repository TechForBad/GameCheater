#include "common.h"

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING registryPath)
{
	UNREFERENCED_PARAMETER(registryPath);

	Printf("Enter DriverEntry");

	// 初始化进程名偏移
    if (!ProcessUtils::InitGetProcessNameOffset(pDriverObject))
    {
        Printf("Error! InitGetProcessNameOffset failed");
        return STATUS_UNSUCCESSFUL;
    }

    // 初始化连接
    if (!ConnUtils::InitConnection())
    {
        Printf("Error! InitConnection failed");
        return STATUS_UNSUCCESSFUL;
    }

	Printf("Leave DriverEntry");
	return STATUS_SUCCESS;
}
