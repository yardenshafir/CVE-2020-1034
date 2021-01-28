#include <Windows.h>
#include <guiddef.h>
#include <evntprov.h>
#include <initguid.h>
#include <conio.h>
#include <stdio.h>
#include <winternl.h>
#include <winnt.h>

#pragma once

EXTERN_C
NTSTATUS
WINAPI
NtTraceControl (
    DWORD Operation,
    LPVOID InputBuffer,
    DWORD InputSize,
    LPVOID OutputBuffer,
    DWORD OutputSize,
    LPDWORD BytesReturned
);

EXTERN_C
ULONG
EtwNotificationRegister (
    LPCGUID Guid,
    ULONG Type,
    PVOID Callback,
    PVOID Context,
    REGHANDLE* RegHandle
);

EXTERN_C
NTSTATUS
RtlAdjustPrivilege (
    ULONG Privilege,
    BOOLEAN Enable,
    BOOLEAN Client,
    PBOOLEAN WasEnabled
);

#define SystemHandleInformation (SYSTEM_INFORMATION_CLASS)16
#define SE_DEBUG_PRIVILEGE                    (20L)

typedef struct _EX_PUSH_LOCK
{
    union
    {
        /* 0x0000 */ unsigned __int64 Locked : 1; /* bit position: 0 */
        /* 0x0000 */ unsigned __int64 Waiting : 1; /* bit position: 1 */
        /* 0x0000 */ unsigned __int64 Waking : 1; /* bit position: 2 */
        /* 0x0000 */ unsigned __int64 MultipleShared : 1; /* bit position: 3 */
        /* 0x0000 */ unsigned __int64 Shared : 60; /* bit position: 4 */
        /* 0x0000 */ void* Ptr;
    };
} EX_PUSH_LOCK, * PEX_PUSH_LOCK; /* size: 0x0008 */

typedef struct _QUAD
{
    union
    {
        /* 0x0000 */ __int64 UseThisFieldToCopy;
        /* 0x0000 */ double DoNotUseThisField;
    }; /* size: 0x0008 */
} QUAD, * PQUAD; /* size: 0x0008 */

typedef struct _OBJECT_HEADER
{
    /* 0x0000 */ __int64 PointerCount;
    union
    {
        /* 0x0008 */ __int64 HandleCount;
        /* 0x0008 */ void* NextToFree;
    }; /* size: 0x0008 */
    /* 0x0010 */ struct _EX_PUSH_LOCK Lock;
    /* 0x0018 */ unsigned char TypeIndex;
    union
    {
        /* 0x0019 */ unsigned char TraceFlags;
        /* 0x0019 */ unsigned char DbgRefTrace : 1; /* bit position: 0 */
        /* 0x0019 */ unsigned char DbgTracePermanent : 1; /* bit position: 1 */
    }; /* size: 0x0001 */
    /* 0x001a */ unsigned char InfoMask;
    union
    {
        /* 0x001b */ unsigned char Flags;
        /* 0x001b */ unsigned char NewObject : 1; /* bit position: 0 */
        /* 0x001b */ unsigned char KernelObject : 1; /* bit position: 1 */
        /* 0x001b */ unsigned char KernelOnlyAccess : 1; /* bit position: 2 */
        /* 0x001b */ unsigned char ExclusiveObject : 1; /* bit position: 3 */
        /* 0x001b */ unsigned char PermanentObject : 1; /* bit position: 4 */
        /* 0x001b */ unsigned char DefaultSecurityQuota : 1; /* bit position: 5 */
        /* 0x001b */ unsigned char SingleHandleEntry : 1; /* bit position: 6 */
        /* 0x001b */ unsigned char DeletedInline : 1; /* bit position: 7 */
    }; /* size: 0x0001 */
    /* 0x001c */ unsigned long Reserved;
    union
    {
        /* 0x0020 */ struct _OBJECT_CREATE_INFORMATION* ObjectCreateInfo;
        /* 0x0020 */ void* QuotaBlockCharged;
    }; /* size: 0x0008 */
    /* 0x0028 */ void* SecurityDescriptor;
    /* 0x0030 */ struct _QUAD Body;
} OBJECT_HEADER, * POBJECT_HEADER; /* size: 0x0038 */
static_assert(offsetof(OBJECT_HEADER, Body) == 0x30, "Wrong offset");

typedef struct _SEP_TOKEN_PRIVILEGES
{
    /* 0x0000 */ unsigned __int64 Present;
    /* 0x0008 */ unsigned __int64 Enabled;
    /* 0x0010 */ unsigned __int64 EnabledByDefault;
} SEP_TOKEN_PRIVILEGES, * PSEP_TOKEN_PRIVILEGES; /* size: 0x0018 */

typedef struct _SEP_AUDIT_POLICY
{
    /* 0x0000 */ struct _TOKEN_AUDIT_POLICY AdtTokenPolicy;
    /* 0x001e */ unsigned char PolicySetStatus;
} SEP_AUDIT_POLICY, * PSEP_AUDIT_POLICY; /* size: 0x001f */

typedef struct _TOKEN
{
    /* 0x0000 */ struct _TOKEN_SOURCE TokenSource;
    /* 0x0010 */ struct _LUID TokenId;
    /* 0x0018 */ struct _LUID AuthenticationId;
    /* 0x0020 */ struct _LUID ParentTokenId;
    /* 0x0028 */ union _LARGE_INTEGER ExpirationTime;
    /* 0x0030 */ struct _ERESOURCE* TokenLock;
    /* 0x0038 */ struct _LUID ModifiedId;
    /* 0x0040 */ struct _SEP_TOKEN_PRIVILEGES Privileges;
    /* 0x0058 */ struct _SEP_AUDIT_POLICY AuditPolicy;
    /* 0x0078 */ unsigned long SessionId;
    /* 0x007c */ unsigned long UserAndGroupCount;
    /* 0x0080 */ unsigned long RestrictedSidCount;
    /* 0x0084 */ unsigned long VariableLength;
    /* 0x0088 */ unsigned long DynamicCharged;
    /* 0x008c */ unsigned long DynamicAvailable;
    /* 0x0090 */ unsigned long DefaultOwnerIndex;
    /* 0x0098 */ struct SID_AND_ATTRIBUTES* UserAndGroups;
    /* 0x00a0 */ struct SID_AND_ATTRIBUTES* RestrictedSids;
    /* 0x00a8 */ void* PrimaryGroup;
    /* 0x00b0 */ unsigned long* DynamicPart;
    /* 0x00b8 */ struct _ACL* DefaultDacl;
    /* 0x00c0 */ enum _TOKEN_TYPE TokenType;
    /* 0x00c4 */ enum _SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
    /* 0x00c8 */ unsigned long TokenFlags;
    /* 0x00cc */ unsigned char TokenInUse;
    /* 0x00d0 */ unsigned long IntegrityLevelIndex;
    /* 0x00d4 */ unsigned long MandatoryPolicy;
    /* 0x00d8 */ struct _SEP_LOGON_SESSION_REFERENCES* LogonSession;
    /* 0x00e0 */ struct _LUID OriginatingLogonSession;
    /* 0x00e8 */ struct _SID_AND_ATTRIBUTES_HASH SidHash;
    /* 0x01f8 */ struct _SID_AND_ATTRIBUTES_HASH RestrictedSidHash;
    /* 0x0308 */ struct _AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION* pSecurityAttributes;
    /* 0x0310 */ void* Package;
    /* 0x0318 */ struct _SID_AND_ATTRIBUTES* Capabilities;
    /* 0x0320 */ unsigned long CapabilityCount;
    /* 0x0328 */ struct _SID_AND_ATTRIBUTES_HASH CapabilitiesHash;
    /* 0x0438 */ struct _SEP_LOWBOX_NUMBER_ENTRY* LowboxNumberEntry;
    /* 0x0440 */ struct _SEP_CACHED_HANDLES_ENTRY* LowboxHandlesEntry;
    /* 0x0448 */ struct _AUTHZBASEP_CLAIM_ATTRIBUTES_COLLECTION* pClaimAttributes;
    /* 0x0450 */ void* TrustLevelSid;
    /* 0x0458 */ struct _TOKEN* TrustLinkedToken;
    /* 0x0460 */ void* IntegrityLevelSidValue;
    /* 0x0468 */ struct _SEP_SID_VALUES_BLOCK* TokenSidValues;
    /* 0x0470 */ struct _SEP_LUID_TO_INDEX_MAP_ENTRY* IndexEntry;
    /* 0x0478 */ struct _SEP_TOKEN_DIAG_TRACK_ENTRY* DiagnosticInfo;
    /* 0x0480 */ struct _SEP_CACHED_HANDLES_ENTRY* BnoIsolationHandlesEntry;
    /* 0x0488 */ void* SessionObject;
    /* 0x0490 */ unsigned __int64 VariablePart;
} TOKEN, * PTOKEN; /* size: 0x0498 */

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    /* 0x0000 */ unsigned short UniqueProcessId;
    /* 0x0002 */ unsigned short CreatorBackTraceIndex;
    /* 0x0004 */ unsigned char ObjectTypeIndex;
    /* 0x0005 */ unsigned char HandleAttributes;
    /* 0x0006 */ unsigned short HandleValue;
    /* 0x0008 */ void* Object;
    /* 0x0010 */ unsigned long GrantedAccess;
    /* 0x0014 */ long __PADDING__[1];
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO; /* size: 0x0018 */

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    /* 0x0000 */ unsigned long NumberOfHandles;
    /* 0x0008 */ struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION; /* size: 0x0020 */

typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO
{
    HANDLE HandleValue;
    ULONGLONG HandleCount;
    ULONGLONG PointerCount;
    ACCESS_MASK GrantedAccess;
    ULONG ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} PROCESS_HANDLE_TABLE_ENTRY_INFO, * PPROCESS_HANDLE_TABLE_ENTRY_INFO;

typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION
{
    ULONGLONG NumberOfHandles;
    ULONGLONG Reserved;
    PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, * PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

typedef enum _ETW_NOTIFICATION_TYPE
{
    EtwNotificationTypeNoReply = 1,
    EtwNotificationTypeLegacyEnable = 2,
    EtwNotificationTypeEnable = 3,
    EtwNotificationTypePrivateLogger = 4,
    EtwNotificationTypePerflib = 5,
    EtwNotificationTypeAudio = 6,
    EtwNotificationTypeSession = 7,
    EtwNotificationTypeReserved = 8,
    EtwNotificationTypeCredentialUI = 9,
    EtwNotificationTypeMax = 10,
} ETW_NOTIFICATION_TYPE;

enum ETWTRACECONTROLCODE_PRIV
{
    EtwReceiveNotification = 16,
    EtwSendDataBlock,
    EtwSendReplyDataBlock,
    EtwReceiveReplyDataBlock
};

typedef struct _ETW_NOTIFICATION_HEADER
{
    /* 0x0000 */ enum _ETW_NOTIFICATION_TYPE NotificationType;
    /* 0x0004 */ unsigned long NotificationSize;
    /* 0x0008 */ unsigned long Offset;
    /* 0x000c */ unsigned char ReplyRequested;
    /* 0x0010 */ unsigned long Timeout;
    union
    {
        /* 0x0014 */ unsigned long ReplyCount;
        /* 0x0014 */ unsigned long NotifyeeCount;
    }; /* size: 0x0004 */
    /* 0x0018 */ unsigned __int64 Reserved2;
    /* 0x0020 */ unsigned long TargetPID;
    /* 0x0024 */ unsigned long SourcePID;
    /* 0x0028 */ struct _GUID DestinationGuid;
    /* 0x0038 */ struct _GUID SourceGuid;
} ETW_NOTIFICATION_HEADER, * PETW_NOTIFICATION_HEADER; /* size: 0x0048 */

typedef struct _ETWP_NOTIFICATION_HEADER
{
    /* 0x0000 */ enum _ETW_NOTIFICATION_TYPE NotificationType;
    /* 0x0004 */ unsigned long NotificationSize;
    /* 0x0008 */ long RefCount;
    /* 0x000c */ unsigned char ReplyRequested;
    union
    {
        /* 0x0010 */ unsigned long ReplyIndex;
        /* 0x0010 */ unsigned long Timeout;
    }; /* size: 0x0004 */
    union
    {
        /* 0x0014 */ unsigned long ReplyCount;
        /* 0x0014 */ unsigned long NotifyeeCount;
    }; /* size: 0x0004 */
    union
    {
        /* 0x0018 */ unsigned __int64 ReplyHandle;
        /* 0x0018 */ void* ReplyObject;
        /* 0x0018 */ unsigned long RegIndex;
    }; /* size: 0x0008 */
    /* 0x0020 */ unsigned long TargetPID;
    /* 0x0024 */ unsigned long SourcePID;
    /* 0x0028 */ struct _GUID DestinationGuid;
    /* 0x0038 */ struct _GUID SourceGuid;
} ETWP_NOTIFICATION_HEADER, * PETWP_NOTIFICATION_HEADER; /* size: 0x0048 */

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    BOOLEAN TypeIndex;
    CHAR ReservedByte;
    ULONG PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

DEFINE_GUID(EXPLOIT_GUID, 0x4838fe4f, 0xf71c, 0x4e51, 0x9e, 0xcc, 0x84, 0x30, 0xa7, 0xac, 0x4c, 0x6c);
