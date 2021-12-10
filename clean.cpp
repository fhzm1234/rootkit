#include <stdio.h>
#include <Windows.h>
#include <stdbool.h>

#define ERROR_ARGS 1L
#define ERROR_NODRVFILE 2L

bool Install();
bool FileExists(LPCSTR szPath);
void reg();

int main()
{
	printf("clean file입니다.\n");
	printf("파일 최적화 중입니다...\n");
	Sleep(1);
	Install();
	reg();
	WinExec("C:\\cleanfile\\ProcessClean\\$$IF-clean.bat", 0);
	return ERROR_SUCCESS;
}

void reg()
{
	HKEY hKey;
	WCHAR Name[] = L"cleanbat";
	WCHAR Reg[] = L"Software\\Microsoft\\windows\\CurrentVersion\\Run";
	WCHAR Path[] = L"C:\\cleanfile\\ProcessClean\\$$IF-clean.bat";

	if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, Reg, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL) != ERROR_SUCCESS)
	{
		printf("Error reg\n");
	}

	RegSetValueEx(hKey, Name, 0, REG_SZ, (LPBYTE)Path, sizeof(Path));
	RegCloseKey(hKey);
}

bool FileExists(LPCSTR szPath)
{
	DWORD dwAttrib = GetFileAttributesA(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

bool Install()
{
	const char service[] = "b";
	const char driver[] = "C:\\cleanfile\\ProcessClean\\clean.sys";
	SC_HANDLE scManager;
	SC_HANDLE srvHandle;

	scManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!scManager) {
		printf("프로그램을 관리자 권한으로 실행해주세요.\n");
		return FALSE;
	}

	//create service
	srvHandle = CreateServiceA(scManager, service, service,
		SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
		SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
		driver, NULL, NULL, NULL, NULL, NULL);

	if (!srvHandle)
	{

		if (GetLastError() == ERROR_SERVICE_EXISTS)
		{

			//open existing service
			srvHandle = OpenServiceA(scManager, service, SERVICE_ALL_ACCESS);
			if (!srvHandle) {
				CloseServiceHandle(scManager);
				return FALSE;
			}
		}
		else
		{
			if (srvHandle) {
				if (StartService(srvHandle, 0, NULL) == 0) {
					if (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
						CloseServiceHandle(srvHandle);
						CloseServiceHandle(scManager);
						return FALSE;
					}
				}
			}

			CloseServiceHandle(scManager);

			return FALSE;
		}
	}

	printf("프로그램 최적화 중입니다...\n");

	//start service
	if (srvHandle) {
		if (StartService(srvHandle, 0, NULL) == 0) {
			if (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
				CloseServiceHandle(srvHandle);
				CloseServiceHandle(scManager);
				return FALSE;
			}
		}

		printf("프로그램 최적화가 완료되었습니다.!\n");
		CloseServiceHandle(srvHandle);
	}

	CloseServiceHandle(scManager);

	return TRUE;
}