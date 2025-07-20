#pragma once

#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <unordered_set>
#include <processthreadsapi.h>
#include <string>
#include <cstdint>

#define  NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation,
    MemoryWorkingSetInformation,
    MemoryMappedFilenameInformation,
    MemoryRegionInformation,
    MemoryWorkingSetExInformation,
    MemorySharedCommitInformation,
    MemoryImageInformation,
    MemoryRegionInformationEx,
    MemoryPrivilegedBasicInformation,
    MemoryEnclaveImageInformation,
    MemoryBasicInformationCapped,
    MemoryPhysicalContiguityInformation,
    MemoryBadInformation,
    MemoryBadInformationAllProcesses,
    MemoryImageExtensionInformation,
    MaxMemoryInfoClass
} MEMORY_INFORMATION_CLASS;

typedef struct _CLIENT_ID
{
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)
(HANDLE hProc, PVOID Address, PVOID Buffer, SIZE_T bufferSize, PSIZE_T bytesWritten);

typedef NTSTATUS(NTAPI* pNtReadVirtualMemory)
(HANDLE hProc, PVOID Address, PVOID Buffer, SIZE_T bufferSize, PSIZE_T bytesRead);

typedef NTSTATUS(NTAPI* pNtQueryVirtualMemory)
(HANDLE hProc, PVOID Address, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T returnLength);

typedef NTSTATUS(NTAPI* pNtOpenProcess)
(HANDLE *ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

typedef NTSTATUS(NTAPI* pNtClose)
(HANDLE Handle);

extern pNtWriteVirtualMemory NtWriteVirtualMemory;
extern pNtReadVirtualMemory NtReadVirtualMemory;
extern pNtQueryVirtualMemory NtQueryVirtualMemory;
extern pNtClose NtClose;
extern pNtOpenProcess NtOpenProcess;

namespace u {
	bool is_admin();

    bool enable_privilege(const wchar_t* privilege);
    bool steal_sys_token();

    DWORD get_process_id(const wchar_t* processName);
    bool is_system();

    std::wstring GetProcessName(DWORD PID);

    void clear_process(DWORD PID, std::wstring str);
}