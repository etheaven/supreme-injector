#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <thread>
#include <string>
#include <vector>

/* GetPIDs creates a snapshot of all processes then processes them one by one to find processes with the given process name */
std::vector<DWORD> GetPIDs(std::wstring targetProcessName)
{
	std::vector<DWORD> pids;
	if(targetProcessName == L"")
		return pids; // No process name given
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // All processes
	PROCESSENTRY32W entry; // Current process
	entry.dwSize = sizeof entry;
	if(!Process32FirstW(snap, &entry)) // Start with the first in snapshot
		return pids;
	do {
		if(std::wstring(entry.szExeFile) == targetProcessName)
			pids.emplace_back(entry.th32ProcessID); // Names match, add to list
	}
	while(Process32NextW(snap, &entry)); // Keep going until end of snapshot
	CloseHandle(snap);
	return pids;
}

/* Close all HANDLEs in a std::vector (for cleanup) */
bool CloseVectorHandles(std::vector<HANDLE> vHandles)
{
	bool allSuccess = true;
	for(int i(0); i < vHandles.size(); ++i) {
		if(!CloseHandle(vHandles[i]))
			allSuccess = false;
	}
	return allSuccess;
}

HANDLE GetSonicHandle(std::wstring targetProcessName, std::wstring parentProcessName = L"", DWORD dwDesiredAccess = PROCESS_ALL_ACCESS, BOOL bInheritHandle = FALSE)
{
	if(targetProcessName == L"")
		return NULL; // No target process specified, exit

	HANDLE hTarget = NULL; // Handle to return

						   /* Getting process handle(s) on parent(s) */
	std::vector<HANDLE> vhParentProcesses;
	if(parentProcessName != L"") { // Parent process name specified, using that parent
		std::vector<DWORD> pids = GetPIDs(parentProcessName); // Getting PID of parent process(es) (might be several processes with same image name, trying on all)
		if(pids.empty())
			return NULL;
		for(int i(0); i < pids.size(); ++i) {
			HANDLE hParentProcess = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, TRUE, pids[i]);
			if(hParentProcess == NULL)
				continue;
			vhParentProcesses.push_back(hParentProcess);
		}
	}
	else { // Parent process name NOT specified, using explorer.exe by default
		DWORD explorerPID = NULL;
		HWND hDesktopWindow = GetShellWindow(); // Getting handle on desktop window
		GetWindowThreadProcessId(hDesktopWindow, &explorerPID); // Using desktop window handle to get handle on explorer.exe
		HANDLE hExplorerProcess = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, TRUE, explorerPID);
		if(hExplorerProcess != NULL)
			vhParentProcesses.push_back(hExplorerProcess);
	}
	if(vhParentProcesses.empty()) // Couldn't open any parent process
		return NULL;

	/* Creating job to get instant notification of new child processes */
	HANDLE ioPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, NULL, NULL);
	HANDLE jobObject = CreateJobObject(NULL, NULL);
	if(jobObject == NULL || ioPort == NULL) { // Error, cleanup
		CloseVectorHandles(vhParentProcesses);
		CloseHandle(ioPort);
		CloseHandle(jobObject);
		return NULL;
	}
	JOBOBJECT_ASSOCIATE_COMPLETION_PORT jobIOport;
	jobIOport.CompletionKey = NULL;
	jobIOport.CompletionPort = ioPort;
	BOOL setInfoJobObjStatus = SetInformationJobObject(jobObject, JobObjectAssociateCompletionPortInformation, &jobIOport, sizeof(jobIOport));
	if(!setInfoJobObjStatus) { // Error, cleanup
		CloseVectorHandles(vhParentProcesses);
		CloseHandle(ioPort);
		CloseHandle(jobObject);
		return NULL;
	}
	bool procInJob = false;
	for(int j(0); j < vhParentProcesses.size(); ++j) {
		if(AssignProcessToJobObject(jobObject, vhParentProcesses[j]) && !procInJob)
			procInJob = true;
	}
	if(!procInJob) { // Couldn't add any process to the job, cleanup
		CloseVectorHandles(vhParentProcesses);
		CloseHandle(ioPort);
		CloseHandle(jobObject);
		return NULL;
	}

	/* Preparing synchronisation between threads */
	HANDLE hsNewHandle = CreateSemaphore(NULL, 0, 9999, NULL);
	if(!hsNewHandle) { // Couldn't create semaphore, cleanup
		CloseVectorHandles(vhParentProcesses);
		CloseHandle(ioPort);
		CloseHandle(jobObject);
		return NULL;
	}

	/* Handle-receiver thread */
	bool gotFirstHandle = false;
	bool stopReceiving = false;
	std::vector<HANDLE> vhSonicProcesses;
	std::thread handleReceiver = std::thread([&]() {
		DWORD numberOfBytesTransferred;
		ULONG_PTR completionKey;
		LPOVERLAPPED overlapped;
		while(GetQueuedCompletionStatus(ioPort, &numberOfBytesTransferred, &completionKey, &overlapped, INFINITE)) {
			if(stopReceiving)
				break; // Termination of the handle-receiving thread received
			HANDLE hSonicProcess = OpenProcess(dwDesiredAccess, bInheritHandle, reinterpret_cast<DWORD>(overlapped));
			if(hSonicProcess == NULL)
				continue;
			vhSonicProcesses.push_back(hSonicProcess);
			ReleaseSemaphore(hsNewHandle, 1, NULL);
		}
		return EXIT_SUCCESS;
	});

	/* Handle-checker thread */
	std::thread handleChecker = std::thread([&]() {
		int handlesChecked = 0, handleChecking = 0;
		while(true) {
			WaitForSingleObject(hsNewHandle, INFINITE); // Waiting for receiver thread to signal new handle gathered
			handleChecking = handlesChecked; // Using the number of handle checked to process the right handle in the vector
			++handlesChecked; // Whatever happens, we will consider this handle checked
			TCHAR processImageFileName[MAX_PATH];
			DWORD maxLength = MAX_PATH;
			if(!QueryFullProcessImageName(vhSonicProcesses[handleChecking], NULL, processImageFileName, &maxLength)) { // Couldn't retrieve full process name image
				CloseHandle(vhSonicProcesses[handleChecking]);
				continue;
			}
			std::wstring strProcessImageFileName = std::wstring(processImageFileName);
			size_t posLastDir = strProcessImageFileName.find_last_of(L"\\");
			if(posLastDir == std::string::npos) { // Error, couldn't find the last "\" in the process image file name
				CloseHandle(vhSonicProcesses[handleChecking]);
				continue;
			}
			std::wstring strProcessName = strProcessImageFileName.substr(posLastDir + 1); // Extracting process name only (e.g. C:\Windows\explorer.exe -> explorer.exe)
			if(strProcessName != targetProcessName) { // *Jedi voice* This is not the handle you are looking for
				CloseHandle(vhSonicProcesses[handleChecking]);
				continue;
			}
			/* Handle to target acquired, stopping receiving thread */
			hTarget = vhSonicProcesses[handleChecking];
			stopReceiving = true;
			PostQueuedCompletionStatus(ioPort, NULL, NULL, NULL);
			handleReceiver.join();
			/* Check if other handles have been created by receiving thread while we were processing in this thread */
			if(handlesChecked < vhSonicProcesses.size())
				for(handlesChecked; handlesChecked < vhSonicProcesses.size(); ++handlesChecked)
					CloseHandle(vhSonicProcesses[handlesChecked]);
			return EXIT_SUCCESS;
		}
	});

	/* Awaiting end of threads (the checker thread terminates the receiver) */
	handleChecker.join();

	/* Cleanup before returning handle */
	CloseVectorHandles(vhParentProcesses);
	CloseHandle(ioPort);
	CloseHandle(jobObject);
	CloseHandle(hsNewHandle);

	return hTarget;
}