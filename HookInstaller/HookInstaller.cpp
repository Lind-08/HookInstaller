#include <iostream>
#include <string>
#include <Windows.h>
#include <TraceLoggingProvider.h>
#include <winmeta.h>

TRACELOGGING_DEFINE_PROVIDER(		// defines g_hProvider
	g_hProvider,					// Name of the provider handle
	"AntiPrinter.injectionDLL",		// Human-readable name for the provider
	// {ce5fa4ea-ab00-5402-8b76-9f76ac858fb5}
	(0xce5fa4ea, 0xab00, 0x5402, 0x8b, 0x76, 0x9f, 0x76, 0xac, 0x85, 0x8f, 0xb5));

int main()
{
	TraceLoggingRegister(g_hProvider);

	//TraceLoggingWrite(
	//	g_hProvider,
	//	"Info",
	//	TraceLoggingValue("sample value", "test message"));

	std::wstring message = L"my message";
	TraceLoggingWrite(
		g_hProvider,
		"Info",
		TraceLoggingWideString(message.c_str(), "message")); // field name is "arg0"


	TraceLoggingUnregister(g_hProvider);
	return 0;

	HOOKPROC hkprcSysMsg;
	HINSTANCE hinstDLL;
	HHOOK hhookSysMsg;

	//char proc_name[MAX_PATH];
	//DWORD proc_name_len = MAX_PATH;
	//BOOL res = QueryFullProcessImageNameA(GetCurrentProcess(), 0, proc_name, &proc_name_len);
	//std::string path(proc_name);
	//std::string base_name = path.substr(path.find_last_of("/\\") + 1);
	//std::cout << base_name << std::endl;
	//return 0;

	hinstDLL = LoadLibrary(TEXT("InjectionDll32.dll"));
	//hinstDLL = LoadLibrary(TEXT("InjectionDll64.dll"));
	hkprcSysMsg = (HOOKPROC)GetProcAddress(hinstDLL, "CallWndProc");

	hhookSysMsg = SetWindowsHookEx(
		WH_CALLWNDPROC,
		hkprcSysMsg,
		hinstDLL,
		0);

	std::string s;
	std::getline(std::cin, s);

	UnhookWindowsHookEx(hhookSysMsg);
	return 0;
}
