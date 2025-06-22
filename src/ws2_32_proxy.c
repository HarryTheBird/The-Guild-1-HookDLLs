// ws2_32_proxy.c
// MinHook‐Inline‐Hook für ws2_32.dll, filtert nur Aufrufe aus server.dll
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <psapi.h>            // GetModuleInformation
#include <shlwapi.h>          // PathRemoveFileSpecW
#include <malloc.h>           // _alloca
#include <stdint.h>
#include <stdio.h>
#include "MinHook.h"
#include "hooklog.h"

#pragma comment(lib, "MinHook.x86.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "legacy_stdio_definitions.lib")  // für _snprintf_s

// Original-Zeiger
static int (WINAPI *real_recv)(SOCKET, char*, int, int)   = NULL;
static int (WINAPI *real_send)(SOCKET, const char*, int, int) = NULL;

// server.dll Bereich
static uintptr_t serverBase = 0;
static size_t    serverSize = 0;

static void initServerModuleRange(void) {
    HMODULE hServ = GetModuleHandleA("server.dll");
    if (!hServ) return;
    MODULEINFO mi = {0};
    if (GetModuleInformation(GetCurrentProcess(), hServ, &mi, sizeof(mi))) {
        serverBase = (uintptr_t)mi.lpBaseOfDll;
        serverSize = (size_t)mi.SizeOfImage;
        //LOG("[HOOK] server.dll at %p size %zu\n", (void*)mi.lpBaseOfDll, mi.SizeOfImage);
    }
}

static BOOL callerInServer(uintptr_t retAddr) {
    return (retAddr >= serverBase && retAddr < serverBase + serverSize);
}

// -----------------------------------------------------------------------------
// Hooked recv: nur bei Aufrufen aus server.dll unsere Logik
int WINAPI hook_recv(SOCKET s, char *buf, int len, int flags) {
    // lazy init server.dll range
    initServerModuleRange();
    if (!serverBase) {
        return real_recv(s, buf, len, flags);
    }
    // Rücksprung-Adresse ermitteln
    CONTEXT ctx = {0}; 
    ctx.ContextFlags = CONTEXT_CONTROL;
    RtlCaptureContext(&ctx);
#ifdef _M_IX86
    uintptr_t ret = ctx.Eip;
#else
    uintptr_t ret = ctx.Rip;
#endif
    if (!callerInServer(ret)) {
        // nicht aus server.dll: direkt weiterreichen
        return real_recv(s, buf, len, flags);
    }

    LOG("[HOOK] recv from server.dll socket=%u len=%d flags=0x%X\n",
        (unsigned)s, len, flags);

    int result = real_recv(s, buf, len, flags);
    if (result == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
        LOG("[HOOK] swallow WSAEWOULDBLOCK -> return 0\n");
        return 0;
    }
    LOG("[HOOK] recv -> %d\n", result);
    return result;
}

// Hooked send: nur bei server.dll-Aufrufen retry bei WSAEWOULDBLOCK
int WINAPI hook_send(SOCKET s, const char *buf, int len, int flags) {
    // lazy init server.dll range
    initServerModuleRange();
    if (!serverBase) {
        return real_send(s, buf, len, flags);
    }
    CONTEXT ctx = {0}; 
    ctx.ContextFlags = CONTEXT_CONTROL;
    RtlCaptureContext(&ctx);
#ifdef _M_IX86
    uintptr_t ret = ctx.Eip;
#else
    uintptr_t ret = ctx.Rip;
#endif
    if (!callerInServer(ret)) {
        return real_send(s, buf, len, flags);
    }

    LOG("[HOOK] send to server.dll socket=%u len=%d flags=0x%X\n",
        (unsigned)s, len, flags);

    int total = 0;
    while (total < len) {
        int sent = real_send(s, buf + total, len - total, flags);
        if (sent == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) {
                Sleep(1);
                continue;
            }
            LOG("[HOOK] send error %d\n", err);
            return SOCKET_ERROR;
        }
        total += sent;
    }
    LOG("[HOOK] send total=%d\n", total);
    return total;
}

// -----------------------------------------------------------------------------
// DLL-Einstieg: Logging öffnen, server.dll-Bereich ermitteln, Hooks installieren
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID _) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);
        InitializeCriticalSection(&logLock);

        // hook.log im DLL-Verzeichnis
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(hinst, path, MAX_PATH);
        PathRemoveFileSpecW(path);
        wcscat_s(path, MAX_PATH, L"\\hook_ws2_32.log");
        logFile = CreateFileW(
            path,
            GENERIC_WRITE,
            FILE_SHARE_READ,
            NULL,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        if (logFile != INVALID_HANDLE_VALUE) {
            SetFilePointer(logFile, 0, NULL, FILE_END);
            LOG("[HOOK] DLL_PROCESS_ATTACH -> %ls\n", path);
        }

        // Bereich von server.dll ermitteln
        initServerModuleRange();

        // echte ws2_32.dll laden
        HMODULE hWs = LoadLibraryW(L"ws2_32.dll");
        real_recv = (void*)GetProcAddress(hWs, "recv");
        real_send = (void*)GetProcAddress(hWs, "send");

        // MinHook-Hooks einrichten
        MH_Initialize();
        MH_CreateHookApi(L"ws2_32", "recv", hook_recv, (void**)&real_recv);
        MH_CreateHookApi(L"ws2_32", "send", hook_send, (void**)&real_send);
        MH_EnableHook(MH_ALL_HOOKS);

    } else if (reason == DLL_PROCESS_DETACH) {
        LOG("[HOOK] DLL_PROCESS_DETACH\n");
        if (logFile != INVALID_HANDLE_VALUE) CloseHandle(logFile);
        DeleteCriticalSection(&logLock);
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
    }
    return TRUE;
}