#include <ntddk.h>

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path)
{
    UNREFERENCED_PARAMETER(driver_object);
    UNREFERENCED_PARAMETER(registry_path);

    DbgPrint("Enter DriverEntry");

    DbgPrint("Leave DriverEntry");

    return STATUS_SUCCESS;
}
