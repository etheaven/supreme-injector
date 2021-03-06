#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include "targetver.h"

#include <stdio.h>
#include <tchar.h>
#include <string>

#ifndef __MAIN_H__
#define __MAIN_H__

#define NT_SUCCESS(x) ((x) >= 0)

/* The CLIENT_ID structure contains identifiers of a process and a thread */
typedef struct _CLIENT_ID {
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

/* The UNICODE_STRING structure is used to pass Unicode strings */
typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

/* MSDN-Quote:
The OBJECT_ATTRIBUTES structure specifies attributes that can be applied to objects or object handles by routines
that create objects and/or return handles to objects.
Use the InitializeObjectAttributes macro to initialize the members of the OBJECT_ATTRIBUTES structure.
Note that InitializeObjectAttributes initializes the SecurityQualityOfService member to NULL. If you must specify a non-NULL value,
set the SecurityQualityOfService member after initialization */
typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation = 0,
	ObjectTypeInformation = 2
} OBJECT_INFORMATION_CLASS;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;

#define InitializeObjectAttributes(p, n, a, r, s) \
{ \
	(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
	(p)->RootDirectory = r; \
	(p)->Attributes = a; \
	(p)->ObjectName = n; \
	(p)->SecurityDescriptor = s; \
	(p)->SecurityQualityOfService = NULL; \
}

typedef NTSTATUS(NTAPI *_RtlCreateUserThread)(HANDLE ProcessHandle, PSECURITY_DESCRIPTOR SecurityDescriptor, BOOLEAN CreateSuspended, ULONG StackZeroBits, PULONG StackReserved, PULONG StackCommit, PVOID StartAddress, PVOID StartParameter, PHANDLE ThreadHandle, PCLIENT_ID ClientID);
typedef PIMAGE_NT_HEADERS(NTAPI *_RtlImageNtHeader)(PVOID ModuleAddress);
typedef NTSTATUS(NTAPI *_RtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);
typedef NTSTATUS(NTAPI *_NtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK AccessMask, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientID);
typedef NTSTATUS(NTAPI *_NtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);
typedef NTSTATUS(NTAPI *_NtClose)(HANDLE ObjectHandle);
typedef NTSTATUS(NTAPI *_NtWaitForSingleObject)(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
typedef NTSTATUS(NTAPI *_NtAllocateVirtualMemory)( //ZwAllocateVirtualMemory
	_In_    HANDLE    ProcessHandle,
	_Inout_ PVOID     *BaseAddress,
	_In_    ULONG_PTR ZeroBits,
	_Inout_ PSIZE_T   RegionSize,
	_In_    ULONG     AllocationType,
	_In_    ULONG     Protect
);
typedef NTSTATUS(NTAPI * _NtQueryObject)(
	_In_opt_  HANDLE                   Handle,
	_In_      OBJECT_INFORMATION_CLASS ObjectInformationClass,
	_Out_opt_ PVOID                    ObjectInformation,
	_In_      ULONG                    ObjectInformationLength,
	_Out_opt_ PULONG                   ReturnLength
);
typedef NTSTATUS(NTAPI *_NtQuerySystemInformation)(
	_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_   PVOID                    SystemInformation,
	_In_      ULONG                    SystemInformationLength,
	_Out_opt_ PULONG                   ReturnLength
);

BOOLEAN RtlFreeHeap(
	_In_     PVOID HeapHandle,
	_In_opt_ ULONG Flags,
	_In_     PVOID HeapBase
);



/* Returns the process id of the specified process name */
DWORD GetProcID(std::string ProcName);
/* Function we gonna inject in a process */
DWORD WINAPI FuncThread(LPVOID unused);
/* Check if the specified process is running/existing */
BOOL ProcessExists(std::string process);
/* Returns the address of the specified library */
PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName);
///----------------------------------------------------------------------///

#endif