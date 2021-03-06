#include "stdafx.h"
#include <Windows.h>
#include <iostream>   
#include <string>  
#include <psapi.h>
#define WIN32_LEAN_AND_MEAN
#include <conio.h>
#include <vector>
#include "test.h"

PIMAGE_NT_HEADERS pINH;
PIMAGE_DATA_DIRECTORY pIDD;
PIMAGE_BASE_RELOCATION pIBR;

HMODULE hModule;
HANDLE hProcess, hThread;
PVOID image, mem;
DWORD i, count, nSizeOfImage;
DWORD_PTR delta, OldDelta;
LPWORD list;
PDWORD_PTR p;
BOOLEAN enabled;
NTSTATUS status;

OBJECT_ATTRIBUTES objAttr;
CLIENT_ID cID;

DWORD dwPid = 0;

HHOOK hHook;
BOOL EnableDebugPrivilege(BOOL bEnable)
{
	HANDLE hToken = nullptr;
	LUID luid;

	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) return FALSE;
	if(!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) return FALSE;

	TOKEN_PRIVILEGES tokenPriv;
	tokenPriv.PrivilegeCount = 1;
	tokenPriv.Privileges[0].Luid = luid;
	tokenPriv.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;

	if(!AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) return FALSE;

	return TRUE;
}


int SetHook(char* dllName, char* funcName)
{
	HMODULE hDll;
	FARPROC dllFunction;
	hDll = LoadLibraryA(dllName);
	if (!hDll)
	{
		printf("LoadLibraryA failed\n");
	}
	dllFunction = GetProcAddress(hDll, funcName);
	if(!dllFunction)
	{
		printf("GetProcAddress failed\n");
	}
	printf("DLL 0x%x Func 0x%x\n", hDll, dllFunction);
	hHook = SetWindowsHookEx(WH_KEYBOARD, (HOOKPROC)dllFunction, hDll, 0);
	if(hHook == NULL) {
		return GetLastError();
	}
	return 0;
}

int get_main_thread(unsigned long pID)
{
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if(hThreadSnap == INVALID_HANDLE_VALUE)
		return (FALSE);
	te32.dwSize = sizeof(THREADENTRY32);
	if(!Thread32First(hThreadSnap, &te32)) {
		CloseHandle(hThreadSnap);
		return (FALSE);
	
	}
	do {
		if(te32.th32OwnerProcessID == pID) {
			//printf("MAIN ID      = 0x%06X\n", te32.th32ThreadID);
			CloseHandle(hThreadSnap);
			return te32.th32ThreadID;
		}
	}
	while(Thread32Next(hThreadSnap, &te32));

	CloseHandle(hThreadSnap);
}

DWORD get_pID(std::wstring ProcessName)
{
	HANDLE hPID = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 ProcEntry;
	ProcEntry.dwSize = sizeof(ProcEntry);
	do {
		if(!wcscmp(ProcEntry.szExeFile, ProcessName.c_str())) {
			DWORD dwPID = ProcEntry.th32ProcessID;
			CloseHandle(hPID);
			return dwPID;
		}
	}
	while(Process32Next(hPID, &ProcEntry));
	return 0;
}

int main(int argc, char **argv)
{
	EnableDebugPrivilege(true);

	_RtlImageNtHeader RtlImageNtHeader = (_RtlImageNtHeader)GetLibraryProcAddress("ntdll.dll", "RtlImageNtHeader");
	_RtlAdjustPrivilege RtlAdjustPrivilege = (_RtlAdjustPrivilege)GetLibraryProcAddress("ntdll.dll", "RtlAdjustPrivilege");
	_NtOpenProcess NtOpenProcess = (_NtOpenProcess)GetLibraryProcAddress("ntdll.dll", "NtOpenProcess");
	_NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetLibraryProcAddress("ntdll.dll", "NtWriteVirtualMemory");
	_NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetLibraryProcAddress("ntdll.dll", "NtAllocateVirtualMemory");
	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation");
	_NtClose NtClose = (_NtClose)GetLibraryProcAddress("ntdll.dll", "NtClose");

	std::cout << "Waiting for the process...\n\n";
	std::wstring process = L"FortniteClient-Win64-Shipping.exe";
	process = L"notepad.exe";
	auto inherit = L"EpicGamesLauncher.exe";
	HANDLE hGame = GetSonicHandle(process);
	std::cout << "[ :) ] Got Handle ID: 0x" << std::hex << hGame << std::endl;
	std::cout << "[ .. ] Press ENTER to exit when you are done verifying handle (e.g. with Process Hacker or Process Explorer)" << std::endl;

	RtlAdjustPrivilege(20, TRUE, FALSE, &enabled);
	hModule = GetModuleHandle(NULL);
	pINH = RtlImageNtHeader(hModule);
	nSizeOfImage = pINH->OptionalHeader.SizeOfImage;

	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

	PVOID AllocationStart = NULL;
	status = NtAllocateVirtualMemory(hGame, &AllocationStart, 0, &nSizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (AllocationStart == NULL || !NT_SUCCESS(status)){
		std::cout << "Last error: " << GetLastError() << '\n';
		if(NT_SUCCESS(status))
			std::cout << "NT SUCCEED\n";
		NtClose(hGame);
		_getch();
		return 1;
	}
	auto pid = get_pID(process);
	std::cout << "pID : " << pid << "\n";
	std::cout << "Base addr: 0x" << AllocationStart << "\n";

	const auto main_thread_id = get_main_thread(pid);
	std::cout << "\n\n" << main_thread_id << "\n";

	if(SetHook("D:\\DexEvent.dll", "DexEvent") != 0) {
		printf("Error %d\n", GetLastError());
		return 0;
	}

	_getch();
	NtClose(hGame);
	return 0;
}

PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName)
{
	return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}