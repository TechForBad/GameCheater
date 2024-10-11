#include "common.h"

BOOL IsConnectionCodeCallback(ULONG ulCode)
{
    return ((COMM::TEST_CODE == ulCode) || ((ulCode & 0xFFF00000) == COMM::MSG_PART_PREFIX) || (COMM::CTRL_CODE == ulCode));
}

ULONG ConnectionCallback(ULONG ulCode)
{
    static COMM::PCMSG g_msg = NULL;

    if (COMM::TEST_CODE == ulCode)
    {
        LOG_INFO("test code: 0x%x", ulCode);
        return COMM::TEST_CODE;
    }
    else if ((ulCode & 0xFFF00000) == COMM::MSG_PART_PREFIX)
    {
        static UINT64 temp = 0i64;
        if ((ulCode & 0xFFFF0000) == COMM::MSG_PART_1)
        {
            temp |= (UINT64)(ulCode & 0x0000FFFF) << 00;
        }
        else if ((ulCode & 0xFFFF0000) == COMM::MSG_PART_2)
        {
            temp |= (UINT64)(ulCode & 0x0000FFFF) << 16;
        }
        else if ((ulCode & 0xFFFF0000) == COMM::MSG_PART_3)
        {
            temp |= (UINT64)(ulCode & 0x0000FFFF) << 32;
        }
        else if ((ulCode & 0xFFFF0000) == COMM::MSG_PART_4)
        {
            temp |= (UINT64)(ulCode & 0x0000FFFF) << 48;

            LOG_INFO("msg addr: 0x%llx", temp);
        }

        g_msg = (COMM::PCMSG)temp;
        return ulCode;
    }
    else if (COMM::CTRL_CODE == ulCode)
    {
        if (NULL == g_msg)
        {
            LOG_ERROR("no msg address, control code: 0x%x", ulCode);
            return 0;
        }

        COMM::CMSG msg;

        __try
        {
            // 校验输入
            ProbeInputType(g_msg, COMM::CMSG);

            // 获取输入数据
            RtlCopyMemory(&msg, g_msg, sizeof(COMM::CMSG));

            // 执行操作
            NTSTATUS ntStatus = OperDispatcher::DispatchOper(&msg);
            if (!NT_SUCCESS(ntStatus))
            {
                LOG_ERROR("DispatchOper failed, control code: 0x%x", ulCode);
                return 0;
            }

            // 如果需要输出，则拷贝到输出
            if (msg.needOutput)
            {
                ProbeOutputType(g_msg, COMM::CMSG);
                RtlCopyMemory(g_msg, &msg, sizeof(COMM::CMSG));
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            LOG_ERROR("Trigger Exception 0x%x, control code: 0x%x", GetExceptionCode(), ulCode);
            return 0;
        }

        return ulCode;
    }

    LOG_ERROR("unknown control code: 0x%x", ulCode);
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
    if (!ConnUtils::InitConnection(IsConnectionCodeCallback, ConnectionCallback))
    {
        LOG_ERROR("InitConnection failed");
        return STATUS_UNSUCCESSFUL;
    }

    LOG_INFO("Leave DriverEntry");
	return STATUS_SUCCESS;
}
