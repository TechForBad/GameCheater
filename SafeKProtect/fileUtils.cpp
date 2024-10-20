#include "fileUtils.h"

NTSTATUS FileUtils::LoadFile(PUNICODE_STRING ustrFileName, PVOID* buffer, DWORD* size)
{
	HANDLE hFile;
	OBJECT_ATTRIBUTES oa;
	FILE_STANDARD_INFORMATION fsi;
	IO_STATUS_BLOCK statusBlock;
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

	InitializeObjectAttributes(&oa, ustrFileName, 0, NULL, NULL);
	ntStatus = ZwCreateFile(&hFile, SYNCHRONIZE | STANDARD_RIGHTS_READ, &oa, &statusBlock, NULL, FILE_SYNCHRONOUS_IO_NONALERT | FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, 0, NULL, 0);
	if (!NT_SUCCESS(ntStatus))
	{
        LOG_ERROR("ZwCreateFile failed, ntStatus: 0x%x", ntStatus);
        return ntStatus;
	}

    ntStatus = ZwQueryInformationFile(hFile, &statusBlock, &fsi, sizeof(fsi), FileStandardInformation);
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("ZwQueryInformationFile failed, ntStatus: 0x%x", ntStatus);
        ZwClose(hFile);
        return ntStatus;
    }

    if (0 != fsi.EndOfFile.HighPart)
    {
        LOG_ERROR("file size is too big");
        ZwClose(hFile);
        return ntStatus;
    }

    *size = fsi.EndOfFile.LowPart;
    *buffer = KAlloc(fsi.EndOfFile.LowPart, FALSE, TRUE);
    if (NULL == *buffer)
    {
        LOG_ERROR("KAlloc failed");
        ZwClose(hFile);
        return STATUS_UNSUCCESSFUL;
    }

    LARGE_INTEGER byteOffset;
    byteOffset.QuadPart = 0;
    ntStatus = ZwReadFile(hFile, NULL, NULL, NULL, &statusBlock, *buffer, fsi.EndOfFile.LowPart, &byteOffset, NULL);
    if (STATUS_PENDING == ntStatus)
    {
        ntStatus = ZwWaitForSingleObject(hFile, FALSE, NULL);
    }
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("ZwReadFile failed");
        KFree(*buffer);
        ZwClose(hFile);
        return STATUS_UNSUCCESSFUL;
    }

    ntStatus = statusBlock.Status;
    if (!NT_SUCCESS(ntStatus))
    {
        LOG_ERROR("ZwReadFile failed");
        KFree(*buffer);
        ZwClose(hFile);
        return STATUS_UNSUCCESSFUL;
    }

    ZwClose(hFile);

	return ntStatus;
}
