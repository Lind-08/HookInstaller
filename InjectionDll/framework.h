#pragma once

#define WIN32_LEAN_AND_MEAN             // Исключите редко используемые компоненты из заголовков Windows
// Файлы заголовков Windows
#include <easyhook.h>
#define WINVER NTDDI_WIN7
#define PSAPI_VERSION 2
#include <windows.h>
#include <Psapi.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <winspool.h>
#include <fstream>
#include <chrono>
#include <sstream>
#include <locale>
#include <codecvt>
#include <cwchar>
#include <winmeta.h>
#include <evntprov.h>
#include <TraceLoggingProvider.h>
extern "C" void __declspec(dllexport) __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo);
