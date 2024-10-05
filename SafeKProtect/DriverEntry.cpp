#include "common.h"

ULONG ConnectionCallback(ULONG ulCode)
{
    LOG_INFO("Code: 0x%x", ulCode);

    switch (ulCode)
    {
    case COMM::TEST_CODE:
    {
        LOG_INFO("[TEST CODE]");
        return COMM::TEST_CODE;
    }
    default:
    {
        return 0;
    }
    }

    return 0;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING registryPath)
{
	UNREFERENCED_PARAMETER(registryPath);

	LOG_INFO("Enter DriverEntry");

	// 初始化进程名偏移
    if (!ProcessUtils::InitGetProcessNameOffset(pDriverObject))
    {
        LOG_ERROR("InitGetProcessNameOffset failed");
        return STATUS_UNSUCCESSFUL;
    }

    // 初始化连接
    if (!ConnUtils::InitConnection(ConnectionCallback))
    {
        LOG_ERROR("InitConnection failed");
        return STATUS_UNSUCCESSFUL;
    }

    LOG_INFO("Leave DriverEntry");
	return STATUS_SUCCESS;
}
