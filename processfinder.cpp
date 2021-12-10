#include <Windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <tchar.h>
#include <Psapi.h>

bool ProcessName(HANDLE hProcess)
{
	DWORD dwLen = 0;
	TCHAR szImagePath[MAX_PATH] = { 0, };

	ZeroMemory(szImagePath, sizeof(szImagePath));
	GetModuleFileNameEx(hProcess, NULL, szImagePath, (sizeof(szImagePath) / sizeof(TCHAR)));
	_tprintf(L"Hidden Process Path : %s\n", szImagePath);
	return 0;
}

bool ProcessUser(DWORD dwProcessId)
{
	bool fResult = false;
	HANDLE hSnapshot = NULL;
	PROCESSENTRY32 pe32 = { 0 };

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hSnapshot, &pe32))
		{
			do
			{
				if (pe32.th32ProcessID == dwProcessId)
				{

					fResult = true;
					break;
				}
			} while (Process32Next(hSnapshot, &pe32));
		}
		CloseHandle(hSnapshot);
	}

	return fResult;
}

bool BruteforceProcessId()
{
	HANDLE hProcess = NULL;
	DWORD dwExitCode = 0;
	ULONG ulHiddenProcesses = 0, ulScannedProccesses = 0;

	for (DWORD dwProcessId = 0; dwProcessId < 0x400000; dwProcessId += 4)
	{
		if (dwProcessId == 0 || dwProcessId == 4)
			continue;

		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcessId);
		if (hProcess == NULL)
		{
			if (GetLastError() != ERROR_INVALID_PARAMETER)
			{

				if (!ProcessUser(dwProcessId))
				{
					printf("Hidden process found pid=%d\n", dwProcessId);
					ProcessName(hProcess);
					ulHiddenProcesses++;
				}

			}
			continue;
		}

		ulScannedProccesses++;

		dwExitCode = 0;
		GetExitCodeProcess(hProcess, &dwExitCode);

		if (dwExitCode == ERROR_NO_MORE_ITEMS)
		{
			if (!ProcessUser(dwProcessId))
			{
				printf("Hidden process found pid=%d\n", dwProcessId);
				ProcessName(hProcess);
				ulHiddenProcesses++;
			}
		}

		CloseHandle(hProcess);
	}

	return ulHiddenProcesses > 0 ? true : false;
}

int main()
{
	BruteforceProcessId();
	return 0;
}