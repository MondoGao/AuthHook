#include <Windows.h>
#include <iostream>
#include <io.h>

#define EXENAME "MapleStory.exe"
#define EXEARGS " GameLaunching"
#define DLLNAME "AuthHook.dll"

#ifdef UNICODE
#	undef UNICODE
#endif // UNICODE

void ErrorBox(const char* format, ...)
{
	char szMessage[1024];

	va_list args;
	va_start(args, format);

	vsnprintf(szMessage, 1023, format, args);
	MessageBoxA(NULL, szMessage, "Launch Error", MB_ICONERROR);

	va_end(args);
}

#define ErrorBoxWithCode(msg) ErrorBox(msg" failed: %d", GetLastError());

BOOL LaunchMaple()
{
	if (_access(DLLNAME, 0) == -1)
	{
		ErrorBox("Unable to find %s", DLLNAME);
		return FALSE;
	}

	if (_access(EXENAME, 0) == -1)
	{
		ErrorBox("Unable to find %s", EXENAME);
		return FALSE;
	}

	STARTUPINFOA		MSStartUpInfo;
	PROCESS_INFORMATION	MSProcInfo;

	ZeroMemory(&MSStartUpInfo, sizeof(MSStartUpInfo));
	ZeroMemory(&MSProcInfo, sizeof(MSProcInfo));

	MSStartUpInfo.cb = sizeof(MSStartUpInfo);

	BOOL createRet = CreateProcessA((LPCSTR)EXENAME, (LPSTR)EXEARGS,
		NULL, NULL, FALSE,
		CREATE_SUSPENDED,
		NULL, NULL, &MSStartUpInfo, &MSProcInfo);

	if (createRet)
	{
		HANDLE hMapleThread = MSProcInfo.hThread;
		HANDLE hMapleProc = MSProcInfo.hProcess;

		const size_t nLoadDllStrLen = strlen(DLLNAME);

		HMODULE hKernel = GetModuleHandleA("Kernel32.dll");

		if (!hKernel)
		{
			ErrorBoxWithCode("GetModuleHandleA");
		}

		LPVOID lpLoadLibAddy = (LPVOID)GetProcAddress(hKernel, "LoadLibraryA");

		if (!lpLoadLibAddy)
		{
			ErrorBoxWithCode("GetProcAddress");
		}

		LPVOID lpRemoteStr = 
			(LPVOID)VirtualAllocEx(hMapleProc, NULL, nLoadDllStrLen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

		if (!lpRemoteStr)
		{
			ErrorBoxWithCode("VirtualAllocEx");
		}

		BOOL nWriteRet = 
			WriteProcessMemory(hMapleProc, (LPVOID)lpRemoteStr, DLLNAME, nLoadDllStrLen, NULL);

		if (!nWriteRet)
		{
			ErrorBoxWithCode("WriteProcessMemory");
		}

		HANDLE hThread = 
			CreateRemoteThread(hMapleProc, NULL, NULL, (LPTHREAD_START_ROUTINE)lpLoadLibAddy, (LPVOID)lpRemoteStr, NULL, NULL);

		if (!hThread)
		{
			ErrorBoxWithCode("CreateRemoteThread");
		}

		DWORD dwRet = ResumeThread(hMapleThread);

		if (dwRet == -1)
		{
			ErrorBoxWithCode("ResumeThread");
		}
		
		CloseHandle(hThread);

		CloseHandle(hMapleThread);
		CloseHandle(hMapleProc);

		ErrorBox("Success");

		return TRUE;
	}
	else
	{
		ErrorBoxWithCode("CreateProcess");
		return FALSE;
	}
}

BOOL IsElevated()
{
	BOOL fRet = FALSE;
	HANDLE hToken = NULL;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize))
		{
			fRet = Elevation.TokenIsElevated;
		}
	}

	if (hToken)
	{
		CloseHandle(hToken);
	}

	return fRet;
}

int CALLBACK WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	if (IsElevated())
	{
		return LaunchMaple();
	}
	else
	{
		ErrorBox("Please run as administrator!");
	}

	return 0;
};