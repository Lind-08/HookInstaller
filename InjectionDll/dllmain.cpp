// dllmain.cpp : Определяет точку входа для приложения DLL.
#include "framework.h"


bool hooked = false;
LPCWSTR testPrinterName[2] = { L"DMPrinter 1", L"DMPrinter 2" };
PPRINTER_NOTIFY_INFO pFakePrinterNotifyInfo = NULL;

TRACELOGGING_DEFINE_PROVIDER(		// defines g_hProvider
    g_hProvider,					// Name of the provider handle
    "AntiPrinter.injectionDLL",		// Human-readable name for the provider
    // {ce5fa4ea-ab00-5402-8b76-9f76ac858fb5}
    (0xce5fa4ea,0xab00,0x5402,0x8b,0x76,0x9f,0x76,0xac,0x85,0x8f,0xb5));


std::string WINAPI GetLastErrorAsString(DWORD errorMessageID)
{
	//Get the error message ID, if any.
	if (errorMessageID == 0) {
		return std::string(); //No error message has been recorded
	}

	LPSTR messageBuffer = nullptr;

	//Ask Win32 to give us the string version of that message ID.
	//The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
	size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), (LPSTR)& messageBuffer, 0, NULL);

	//Copy the error message into a std::string.
	std::string message(messageBuffer, size);

	//Free the Win32's string's buffer.
	LocalFree(messageBuffer);

	return message;
}

std::wstring WINAPI GetLastErrorAsStringW(DWORD errorMessageID)
{
	//Get the error message ID, if any.
	if (errorMessageID == 0) {
		return std::wstring(); //No error message has been recorded
	}

	LPWSTR messageBuffer = nullptr;

	//Ask Win32 to give us the string version of that message ID.
	//The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
	size_t size = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), (LPWSTR)& messageBuffer, 0, NULL);

	//Copy the error message into a std::string.
	std::wstring message(messageBuffer, size);

	//Free the Win32's string's buffer.
	LocalFree(messageBuffer);

	return message;
}

void WINAPI writeToLog(std::wostringstream& message)
{
	TraceLoggingWrite(
        g_hProvider,
        "Info",
        TraceLoggingLevel(WINEVENT_LEVEL_INFO), // Levels defined in <winmeta.h>
        TraceLoggingKeyword(WINEVENT_KEYWORD_EVENTLOG_CLASSIC), // Provider-defined categories
        TraceLoggingWideString(message.str().c_str(), "message")); // field name is "arg0"
	message.str(L"");
	message.clear();
}

std::wstring AnalyzeAndPrintDesiredAccessFlags(DWORD Flags)
{
	std::wostringstream outStream;
	if ((Flags & PRINTER_ACCESS_ADMINISTER) != 0)
		outStream << " PRINTER_ACCESS_ADMINISTER";
	if ((Flags & PRINTER_ACCESS_USE) != 0)
		outStream << " PRINTER_ACCESS_USE";
#if (NTDDI_VERSION >= NTDDI_WINBLUE)
	if ((Flags & PRINTER_ACCESS_MANAGE_LIMITED) != 0)
		outStream << " PRINTER_ACCESS_MANAGE_LIMITED";
#endif // (NTDDI_VERSION >= NTDDI_WINBLUE)
	if ((Flags & PRINTER_ALL_ACCESS) != 0)
		outStream << " PRINTER_ALL_ACCESS";
	if ((Flags & DELETE) != 0)
		outStream << " DELETE";
	if ((Flags & READ_CONTROL) != 0)
		outStream << " READ_CONTROL";
	if ((Flags & SYNCHRONIZE) != 0)
		outStream << " SYNCHRONIZE";
	if ((Flags & WRITE_DAC) != 0)
		outStream << " WRITE_DAC";
	if ((Flags & WRITE_OWNER) != 0)
		outStream << " WRITE_OWNER";
	return outStream.str();
}

BOOL WINAPI myOpenPrinterA(
	_In_  LPSTR             pPrinterName,
	_Out_ LPHANDLE           phPrinter,
	_In_  LPPRINTER_DEFAULTSA pDefault
)
{
	std::wostringstream outStream;
	outStream << L"OpenPrinterA called.";
	//*phPrinter = 0;
	auto res = TRUE;
	res = OpenPrinterA(pPrinterName, phPrinter, pDefault);
	auto err = GetLastError();
	if (pPrinterName == NULL)
		outStream << " [pPrinterName]: NULL\n";
	else
		outStream << " [pPrinterName]: " << "\"" << pPrinterName << "\"" << "\n";
	if (phPrinter == NULL)
		outStream << " [phPrinter] <- NULL\n";
	else
		outStream << " [phPrinter] <- " << (unsigned long)phPrinter << "\n";
	if (pDefault == NULL)
		outStream << " [pDefault]: NULL\n";
	else
	{
		if (pDefault->DesiredAccess != NULL)
		{
			outStream << " [pDefault.DesiredAccess]: ";
			outStream << AnalyzeAndPrintDesiredAccessFlags(pDefault->DesiredAccess) << "\n";
		}
		else
			outStream << " [pDefault.DesiredAccess]: NULL\n";
	}
	if (res == FALSE)
		outStream << " [return] <- FALSE [error] " << err << " |";
	else
		outStream << " [return] <- TRUE |";
	writeToLog(outStream);
	return res;
	}

BOOL WINAPI myOpenPrinterW(
	_In_  LPTSTR             pPrinterName,
	_Out_ LPHANDLE           phPrinter,
	_In_  LPPRINTER_DEFAULTS pDefault
)
{
	std::wostringstream outStream;
	outStream << L"OpenPrinterA called.\n";
	auto res = OpenPrinterW(pPrinterName, phPrinter, pDefault);
	auto err = GetLastError();
	if (pPrinterName == NULL)
		outStream << " [pPrinterName]: NULL\n";
	else
		outStream << " [pPrinterName]: " << "\"" << pPrinterName << "\"" << "\n";
	if (phPrinter == NULL)
		outStream << " [phPrinter] <- NULL\n";
	else
		outStream << " [phPrinter] <- " << (unsigned long)phPrinter << "\n";
	if (pDefault == NULL)
		outStream << " [pDefault]: NULL\n";
	else
	{
		if (pDefault->DesiredAccess != NULL)
		{
			outStream << " [pDefault.DesiredAccess]: ";
			outStream << AnalyzeAndPrintDesiredAccessFlags(pDefault->DesiredAccess) << "\n";
		}
		else
			outStream << " [pDefault.DesiredAccess]: NULL\n";
	}
	if (res == FALSE)
		outStream << " [return] <- FALSE [error] " << err << " |";
	else
		outStream << " [return] <- TRUE |";
	writeToLog(outStream);
	return res;
}

BOOL WINAPI myGetDefaultPrinterW(
	_In_    LPWSTR  pszBuffer,
	_Inout_ LPDWORD pcchBuffer
)
{
	std::wostringstream outStream;
	outStream << L"GetDefaultPrinterW called.";

	//SetLastError(ERROR_FILE_NOT_FOUND);		// Отсутствует принтер по-умолчанию
	//return FALSE;

	if (pcchBuffer == NULL)
	{
		outStream << L" [pcchBuffer]: NULL";
		outStream << L" [return] <- FALSE [error] |";
		writeToLog(outStream);
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		return FALSE;
	}
	BOOL res;
	if (pszBuffer == NULL)
	{
		*pcchBuffer = std::wcslen(testPrinterName[0]) + 1;
		outStream << L" [pszBuffer]: NULL [pcchBuffer] <- " << *pcchBuffer;
		outStream << L" [return] <- FALSE [error] ERROR_INSUFFICIENT_BUFFER |";
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		res = FALSE;
	}
	else
	{
		outStream << L" [pszBuffer] <- \"" << pszBuffer << "\" [pcchBuffer] <- " << *pcchBuffer;
		DWORD prNameLen = std::wcslen(testPrinterName[0]) + 1;
		if (prNameLen > *pcchBuffer) {
			outStream << L" [return] <- FALSE [error] ERROR_INSUFFICIENT_BUFFER |";
			*pcchBuffer = prNameLen;
			SetLastError(ERROR_INSUFFICIENT_BUFFER);
			res = FALSE;
		}
		else {
			std::wcscpy(pszBuffer, testPrinterName[0]);
			*pcchBuffer = prNameLen;
			res = TRUE;
			outStream << L" Modified: [pszBuffer] <- \"" << pszBuffer << "\" [pcchBuffer] <- " << *pcchBuffer;
			outStream << L" [return] <- TRUE |";
		}
	}
	writeToLog(outStream);
	return res;
}

BOOL WINAPI myGetDefaultPrinterA(
	_In_    LPSTR  pszBuffer,
	_Inout_ LPDWORD pcchBuffer
)
{
	std::wostringstream outStream;
	outStream << L"GetDefaultPrinterA called.";
	auto res = GetDefaultPrinterA(pszBuffer, pcchBuffer);
	auto err = GetLastError();
	if (pszBuffer == NULL)
	{
		outStream << L" [pszBuffer]: NULL [pcchBuffer] <- " << *pcchBuffer;
		outStream << " [return] <- FALSE [error] " << err << " |";
	}
	else
	{
		outStream << L" [pszBuffer] <- \"" << pszBuffer << "\" [pcchBuffer] <- " << *pcchBuffer << " [return] TRUE |";
	}
	writeToLog(outStream);
	return res;
}

std::wstring AnalyzeAndPrintEnumPrintersFlags(DWORD Flags)
{
	std::wostringstream outStream;
	if ((Flags & PRINTER_ENUM_LOCAL) != 0)
		outStream << " PRINTER_ENUM_LOCAL";
	if ((Flags & PRINTER_ENUM_NAME) != 0)
		outStream << " PRINTER_ENUM_NAME";
	if ((Flags & PRINTER_ENUM_SHARED) != 0)
		outStream << " PRINTER_ENUM_SHARED";
	if ((Flags & PRINTER_ENUM_CONNECTIONS) != 0)
		outStream << " PRINTER_ENUM_CONNECTIONS";
	if ((Flags & PRINTER_ENUM_NETWORK) != 0)
		outStream << " PRINTER_ENUM_NETWORK";
	if ((Flags & PRINTER_ENUM_REMOTE) != 0)
		outStream << " PRINTER_ENUM_REMOTE";
#if (NTDDI_VERSION >= NTDDI_WINBLUE)
	if ((Flags & PRINTER_ENUM_CATEGORY_3D) != 0)
		outStream << " PRINTER_ENUM_CATEGORY_3D";
	if ((Flags & PRINTER_ENUM_CATEGORY_ALL) != 0)
		outStream << " PRINTER_ENUM_CATEGORY_ALL";
#endif // (NTDDI_VERSION >= NTDDI_WINBLUE)
	return outStream.str();
}

BOOL WINAPI myEnumPrintersA(
	_In_  DWORD   Flags,
	_In_  LPSTR  Name,
	_In_  DWORD   Level,
	_Out_ LPBYTE  pPrinterEnum,
	_In_  DWORD   cbBuf,
	_Out_ LPDWORD pcbNeeded,
	_Out_ LPDWORD pcReturned)
{
	std::wostringstream outStream;
	outStream << L"EnumPrintersA called.\n";
	auto res = EnumPrintersA(Flags, Name, Level, pPrinterEnum, cbBuf, pcbNeeded, pcReturned);
	auto err = GetLastError();
	outStream << " [Flags]: ";
	outStream << AnalyzeAndPrintEnumPrintersFlags(Flags) << "\n";
	outStream << " [Name]: ";
	if (Name == NULL)
		outStream << "NULL\n";
	else
		outStream << Name << "\n";
	outStream << " [Level]: " << Level << "\n";
	outStream << " [pPrinterEnum]: ";
	if (pPrinterEnum == NULL)
		outStream << "NULL\n";
	else
		outStream << *pPrinterEnum << "\n";
	outStream << " [cbBuf]: " << cbBuf << "\n";
	outStream << " [pcbNeeded] <- " << *pcbNeeded << "\n";
	outStream << " [pcReturned] <- " << *pcReturned << "\n";
	if (res == NULL)
	{
		outStream << " [return] <- FALSE [error] " << err << " |";
	}
	else
		outStream << " [return] <- TRUE |";
	writeToLog(outStream);
	return res;
}

BOOL WINAPI myEnumPrintersW(
	_In_  DWORD   Flags,
	_In_  LPTSTR  Name,
	_In_  DWORD   Level,
	_Out_ LPBYTE  pPrinterEnum,
	_In_  DWORD   cbBuf,
	_Out_ LPDWORD pcbNeeded,
	_Out_ LPDWORD pcReturned)
{
	std::wostringstream outStream;
	outStream << L"EnumPrintersW called.\n";
	BOOL res = EnumPrintersW(Flags, Name, Level, pPrinterEnum, cbBuf, pcbNeeded, pcReturned);

	auto err = GetLastError();
	outStream << " [Flags]: ";
	outStream << AnalyzeAndPrintEnumPrintersFlags(Flags) << "\n";
	outStream << " [Name]: ";
	if (Name == NULL)
		outStream << "NULL\n";
	else
		outStream << Name << "\n";
	outStream << " [Level]: " << Level << "\n";
	outStream << " [pPrinterEnum]: ";
	if (pPrinterEnum == NULL)
		outStream << "NULL\n";
	else
		outStream << *pPrinterEnum << "\n";
	outStream << " [cbBuf]: " << cbBuf << "\n";
	outStream << " [pcbNeeded] <- " << *pcbNeeded << "\n";
	outStream << " [pcReturned] <- " << *pcReturned << "\n";
	if (res == NULL)
	{
		outStream << " [return] <- FALSE [error] " << err << " |";
	}
	else
		outStream << " [return] <- TRUE |";

	writeToLog(outStream);

	if (Level == 4 && *pcReturned != 0 && pPrinterEnum) {
		PRINTER_INFO_4* prInfoBuf = (PRINTER_INFO_4*)pPrinterEnum;
		int num_printers = *pcReturned;
		outStream << L"Found " << num_printers << " printers. Printer list:\n";
		int bytes_sum = 0;
		for (int i = 0; i < num_printers; i++)
		{
			int bytes = (std::wcslen(prInfoBuf[i].pPrinterName) + 1) * 2;
			if (prInfoBuf[i].pServerName)
				bytes += (std::wcslen(prInfoBuf[i].pServerName) + 1) * 2;
			bytes += sizeof(PRINTER_INFO_4);
			bytes_sum += bytes;
			outStream << "\t" << i << ". " << prInfoBuf[i].pPrinterName << " " << bytes << "\n";
			if (std::wcscmp(prInfoBuf[i].pPrinterName, testPrinterName[0]) == 0 ||
				std::wcscmp(prInfoBuf[i].pPrinterName, testPrinterName[1]) == 0) {
				memcpy(prInfoBuf, prInfoBuf + i, sizeof(PRINTER_INFO_4));
				*pcReturned = 1;
				outStream << L"Found printer: " << testPrinterName << L" Modifying printer list";
				writeToLog(outStream);
				break;
			}
		}
		outStream << L"Sum string bytes: " << bytes_sum << "\n";
		writeToLog(outStream);
	}
	return res;
}

HANDLE
WINAPI
myFindFirstPrinterChangeNotification(
	_In_     HANDLE hPrinter,
			 DWORD  fdwFilter,
			 DWORD  fdwOptions,
	_In_opt_ PVOID  pPrinterNotifyOptions
)
{
	std::wostringstream outStream;
	outStream << L"FindFirstPrinterChangeNotification called.";
	HANDLE hNotify = FindFirstPrinterChangeNotification(hPrinter, fdwFilter, fdwOptions, pPrinterNotifyOptions);
	if (hNotify == INVALID_HANDLE_VALUE)
	{
		outStream << L" FindFirstPrinterChangeNotification error ";
	}
	else
	{
		outStream << L" [fdwFilter]: " << fdwFilter << " [fdwOptions]: " << fdwOptions;
	}
	writeToLog(outStream);
	return hNotify;
}

BOOL
WINAPI
myFindNextPrinterChangeNotification(
	_In_        HANDLE hChange,
	_Out_opt_   PDWORD pdwChange,
	_In_opt_    LPVOID pvReserved,
	_Out_opt_   LPVOID* ppPrinterNotifyInfo
)
{
	std::wostringstream outStream;
	outStream << L"FindNextPrinterChangeNotification called.";
	BOOL res = FindNextPrinterChangeNotification(hChange, pdwChange, pvReserved, ppPrinterNotifyInfo);
	if (res == FALSE)
	{
		outStream << L" FindNextPrinterChangeNotification error ";
	}
	else
	{
		outStream << L" [pdwChange] <- " << *pdwChange << " [return] <- TRUE |";
	}
	writeToLog(outStream);

	PPRINTER_NOTIFY_INFO ppPrN = (PPRINTER_NOTIFY_INFO)(*ppPrinterNotifyInfo);
	size_t fakePrinterNotifyInfoSize = sizeof(PRINTER_NOTIFY_INFO) + ppPrN->Count * sizeof(PRINTER_NOTIFY_INFO_DATA);
	pFakePrinterNotifyInfo = (PPRINTER_NOTIFY_INFO)(new BYTE[fakePrinterNotifyInfoSize]);
	outStream << L"\n\t" << L"Create fake printer notify info: " << fakePrinterNotifyInfoSize << L" bytes";

	pFakePrinterNotifyInfo->Version = ppPrN->Version;
	pFakePrinterNotifyInfo->Flags = ppPrN->Flags;
	int prn_name_offset = 1;
	int fake_counter = 0;
	int pninfo_types = 10;
	outStream << L"\n\tFound notifies: " << ppPrN->Count;
	//for (int i = 0; i < ppPrN->Count; i++) {
	//	outStream << L"\n\t" << i << L"\tTYPE = " << ppPrN->aData[i].Type << L"\tFIELD = " << ppPrN->aData[i].Field;
	//}
	while (prn_name_offset < ppPrN->Count) {
		outStream << L"\n\tprn_name_offset = " << prn_name_offset << L" fake_counter = " << fake_counter;
		if (ppPrN->aData[prn_name_offset].Type == PRINTER_NOTIFY_TYPE) {
			LPWSTR pName = (LPWSTR)ppPrN->aData[prn_name_offset].NotifyData.Data.pBuf;
			if (std::wcscmp(pName, testPrinterName[0]) == 0) {
				memcpy(&pFakePrinterNotifyInfo->aData[fake_counter], &ppPrN->aData[prn_name_offset-1], pninfo_types * sizeof(PRINTER_NOTIFY_INFO_DATA));
				outStream << L"\n\tFound printer: " << testPrinterName[0] << L" Modifying printer list";
				fake_counter += 10;
			}
			if (std::wcscmp(pName, testPrinterName[1]) == 0) {
				memcpy(&pFakePrinterNotifyInfo->aData[fake_counter], &ppPrN->aData[prn_name_offset - 1], pninfo_types * sizeof(PRINTER_NOTIFY_INFO_DATA));
				outStream << L"\n\tFound printer: " << testPrinterName[1] << L" Modifying printer list";
				fake_counter += 10;
			}
		}
		else {
			//pFakePrinterNotifyInfo->aData[fake_counter] = ppPrN->aData[fake_counter];
			//outStream << L"\n\tCopy notify: " << fake_counter;
			//fake_counter++;
		}
		prn_name_offset += 10;
	}
	pFakePrinterNotifyInfo->Count = fake_counter;
	writeToLog(outStream);

	*ppPrinterNotifyInfo = (LPVOID)pFakePrinterNotifyInfo;

	return res;
}

HMODULE
WINAPI
myLoadLibraryA(
	_In_ LPCSTR lpLibFileName
)
{
	std::wostringstream outStream;
	auto res = LoadLibraryA(lpLibFileName);
	outStream << L"LoadLibraryA called: " << lpLibFileName  << " <-- " << res;
	writeToLog(outStream);
	return res;
}

HMODULE
WINAPI
myLoadLibraryW(
	_In_ LPCWSTR lpLibFileName
)
{
	std::wostringstream outStream;
	auto res = LoadLibraryW(lpLibFileName);
	outStream << L"LoadLibraryW called: " << lpLibFileName << " <-- " << res;
	writeToLog(outStream);
	return res;
}

void installHook()
{

	std::wostringstream outStream;
	//outStream << L"Injected by process Id: " << inRemoteInfo->HostPID;
	//writeToLog(outStream);

	//if (inRemoteInfo->UserDataSize != NULL)
	//{
	//	processPath = std::wstring(reinterpret_cast<wchar_t*>(inRemoteInfo->UserData));
	//}

	// Perform hooking
	HOOK_TRACE_INFO OpenPrinterAHook = { NULL }; // keep track of our hook
	HOOK_TRACE_INFO OpenPrinterWHook = { NULL };
	HOOK_TRACE_INFO GetDefaultPrinterWHook = { NULL };
	HOOK_TRACE_INFO GetDefaultPrinterAHook = { NULL };
	HOOK_TRACE_INFO EnumPrintersAHook = { NULL };
	HOOK_TRACE_INFO EnumPrintersWHook = { NULL };
	HOOK_TRACE_INFO LoadLibraryAHook = { NULL };
	HOOK_TRACE_INFO LoadLibraryWHook = { NULL };
	HOOK_TRACE_INFO FindFirstPrinterChangeNotificationHook = { NULL };
	HOOK_TRACE_INFO FindNextPrinterChangeNotificationHook = { NULL };

	// Enum Loaded Modules
	//ListLoadedModules();

	HMODULE winspl = GetModuleHandleW(L"winspool.drv");
	if (winspl)
	{
		outStream << L"winspool.drv loaded: " << winspl;
	}
	else
	{
		outStream << L"winspool.drv not loaded";
		return;
	}
	writeToLog(outStream);

	//auto winspl = LoadLibraryW(L"winspool.drv");

	//if (winspl == NULL)
	//{
	//	outStream << L"Can't load winspool.drv. Error: " << GetLastError();
	//	writeToLog(outStream);
	//	return;
	//}
	//outStream << L"winspool.drv loaded: " << winspl;
	//writeToLog(outStream);

	//outStream << L"Win32 GetDefaultPrinterW found at address: " << GetProcAddress(winspl, "GetDefaultPrinterW");
	//writeToLog(outStream);
	//outStream << L"Win32 GetDefaultPrinterA found at address: " << GetProcAddress(winspl, "GetDefaultPrinterA");
	//writeToLog(outStream);
	//outStream << L"Win32 OpenPrinterA found at address: " << GetProcAddress(winspl, "OpenPrinterA");
	//writeToLog(outStream);
	//outStream << L"Win32 OpenPrinterW found at address: " << GetProcAddress(winspl, "OpenPrinterW");
	//writeToLog(outStream);
	//outStream << L"Win32 EnumPrintersA found at address: " << GetProcAddress(winspl, "EnumPrintersA");
	//writeToLog(outStream);
	//outStream << L"Win32 EnumPrintersW found at address: " << GetProcAddress(winspl, "EnumPrintersW");
	//writeToLog(outStream);
	//outStream << L"Win32 FindFirstPrinterChangeNotification found at address: " << GetProcAddress(winspl, "FindFirstPrinterChangeNotification");
	//writeToLog(outStream);
	//outStream << L"Win32 FindNextPrinterChangeNotification found at address: " << GetProcAddress(winspl, "FindNextPrinterChangeNotification");
	//writeToLog(outStream);

	// Install the hook
	NTSTATUS result;
	result = LhInstallHook(
		GetProcAddress(winspl, "OpenPrinterA"),
		myOpenPrinterA,
		NULL,
		&OpenPrinterAHook);
	if (FAILED(result))
	{
		std::wstring s(RtlGetLastErrorString());
		outStream << L"Failed to install hook: " << s;
	}
	else
	{
		outStream << L"Hook 'OpenPrinterA' installed successfully.";
	}
	writeToLog(outStream);

	result = LhInstallHook(
		GetProcAddress(winspl, "OpenPrinterW"),
		myOpenPrinterW,
		NULL,
		&OpenPrinterWHook);
	if (FAILED(result))
	{
		std::wstring s(RtlGetLastErrorString());
		outStream << L"Failed to install hook: " << s;
	}
	else
	{
		outStream << L"Hook 'OpenPrinterW' installed successfully.";
	}
	writeToLog(outStream);

	result = LhInstallHook(
		GetProcAddress(winspl, "GetDefaultPrinterW"),
		myGetDefaultPrinterW,
		NULL,
		&GetDefaultPrinterWHook);
	if (FAILED(result))
	{
		std::wstring s(RtlGetLastErrorString());
		outStream << L"Failed to install hook: " << s;
	}
	else
	{
		outStream << L"Hook 'GetDefaultPrinterW' installed successfully.";
	}
	writeToLog(outStream);

	result = LhInstallHook(
		GetProcAddress(winspl, "GetDefaultPrinterA"),
		myGetDefaultPrinterA,
		NULL,
		&GetDefaultPrinterAHook);
	if (FAILED(result))
	{
		std::wstring s(RtlGetLastErrorString());
		outStream << L"Failed to install hook: " << s;
	}
	else
	{
		outStream << L"Hook 'GetDefaultPrinterA' installed successfully.";
	}
	writeToLog(outStream);

	result = LhInstallHook(
		GetProcAddress(winspl, "EnumPrintersA"),
		myEnumPrintersA,
		NULL,
		&EnumPrintersAHook);
	if (FAILED(result))
	{
		std::wstring s(RtlGetLastErrorString());
		outStream << L"Failed to install hook: " << s;
	}
	else
	{
		outStream << L"Hook 'EnumPrintersA' installed successfully.";
	}
	writeToLog(outStream);

	result = LhInstallHook(
		GetProcAddress(winspl, "EnumPrintersW"),
		myEnumPrintersW,
		NULL,
		&EnumPrintersWHook);
	if (FAILED(result))
	{
		std::wstring s(RtlGetLastErrorString());
		outStream << L"Failed to install hook: " << s;
	}
	else
	{
		outStream << L"Hook 'EnumPrintersW' installed successfully.";
	}
	writeToLog(outStream);

	result = LhInstallHook(
		GetProcAddress(winspl, "FindFirstPrinterChangeNotification"),
		myFindFirstPrinterChangeNotification,
		NULL,
		&FindFirstPrinterChangeNotificationHook);
	if (FAILED(result))
	{
		std::wstring s(RtlGetLastErrorString());
		outStream << L"Failed to install hook: " << s;
	}
	else
	{
		outStream << L"Hook 'FindFirstPrinterChangeNotification' installed successfully.";
	}
	writeToLog(outStream);

	result = LhInstallHook(
		GetProcAddress(winspl, "FindNextPrinterChangeNotification"),
		myFindNextPrinterChangeNotification,
		NULL,
		&FindNextPrinterChangeNotificationHook);
	if (FAILED(result))
	{
		std::wstring s(RtlGetLastErrorString());
		outStream << L"Failed to install hook: " << s;
	}
	else
	{
		outStream << L"Hook 'FindNextPrinterChangeNotification' installed successfully.";
	}
	writeToLog(outStream);

	//result = LhInstallHook(
	//	GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA"),
	//	myLoadLibraryA,
	//	NULL,
	//	&LoadLibraryAHook);
	//if (FAILED(result))
	//{
	//	std::wstring s(RtlGetLastErrorString());
	//	outStream << L"Failed to install hook: " << s;
	//}
	//else
	//{
	//	outStream << L"Hook 'LoadLibraryA' installed successfully.";
	//}
	//writeToLog(outStream);

	//result = LhInstallHook(
	//	GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryW"),
	//	myLoadLibraryW,
	//	NULL,
	//	&LoadLibraryWHook);
	//if (FAILED(result))
	//{
	//	std::wstring s(RtlGetLastErrorString());
	//	outStream << L"Failed to install hook: " << s;
	//}
	//else
	//{
	//	outStream << L"Hook 'LoadLibraryW' installed successfully.";
	//}
	//writeToLog(outStream);

	// If the threadId in the ACL is set to 0,
	// then internally EasyHook uses GetCurrentThreadId()
	ULONG ACLEntries[1] = { 0 };

	// Disable the hook for the provided threadIds, enable for all others
	LhSetExclusiveACL(ACLEntries, 1, &OpenPrinterAHook);
	LhSetExclusiveACL(ACLEntries, 1, &OpenPrinterWHook);
	LhSetExclusiveACL(ACLEntries, 1, &GetDefaultPrinterWHook);
	LhSetExclusiveACL(ACLEntries, 1, &GetDefaultPrinterAHook);
	LhSetExclusiveACL(ACLEntries, 1, &EnumPrintersAHook);
	LhSetExclusiveACL(ACLEntries, 1, &EnumPrintersWHook);
	LhSetExclusiveACL(ACLEntries, 1, &FindFirstPrinterChangeNotificationHook);
	LhSetExclusiveACL(ACLEntries, 1, &FindNextPrinterChangeNotificationHook);
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		TraceLoggingRegister(g_hProvider);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		TraceLoggingUnregister(g_hProvider);
		break;
	}
	return TRUE;
}

extern "C" __declspec(dllexport) LRESULT WINAPI CallWndProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	if (!hooked) {
		installHook();
		hooked = true;
	}
	HHOOK  hhk = 0;
	return CallNextHookEx(hhk, nCode, wParam, lParam);
}
