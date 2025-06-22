// server_proxy.c
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <shlwapi.h>
#include "MinHook.h"   // MinHook-Header
#include <stdio.h>
#include "hooklog.h"

#pragma comment(lib, "MinHook.x86.lib")  // oder MinHook.x64.lib
#pragma comment(lib, "Shlwapi.lib")

// -----------------------------------------------------------------------------
// Logging

// -----------------------------------------------------------------------------
// Prototypen der Original-Funktionen in server.dll
typedef int      (WINAPI *pF3720_t)(int *ctx, int received, int totalLen);

// Zeiger auf die echten Funktionen
static pF3720_t  real_F3720  = NULL;

// -----------------------------------------------------------------------------
// Unsere Detour

// 1) High-Level-Receive: bei negativem Return 0 zurückgeben
static int WINAPI detour_F3720(int *ctx, int received, int totalLen) {
    int ret = real_F3720(ctx, received, totalLen);
    LOG("[SERVER HOOK] detour_F3720 called, ret=%d\n", ret);
    if (ret < 0) {
        LOG("[SERVER HOOK] detour_F3720 adjusted negative to 0\n");
        return 0;
    }
    return ret;
}

// -----------------------------------------------------------------------------
// DllMain: MinHook initialisieren, Hooks setzen und Logging

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID _) {
    if (reason == DLL_PROCESS_ATTACH) {
        // Logging init
        InitializeCriticalSection(&logLock);
        {
            wchar_t path[MAX_PATH];
            GetModuleFileNameW(hMod, path, MAX_PATH);
            PathRemoveFileSpecW(path);
            wcscat_s(path, MAX_PATH, L"\\hook_server.log");
            logFile = CreateFileW(
                path, GENERIC_WRITE, FILE_SHARE_READ,
                NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
            );
            if (logFile != INVALID_HANDLE_VALUE) {
                SetFilePointer(logFile, 0, NULL, FILE_END);
                LOG("[SERVER HOOK] DLL_PROCESS_ATTACH -> %ls\n", path);
            }
        }

        // MinHook init
        if (MH_Initialize() != MH_OK) {
            LOG("[SERVER HOOK] MH_Initialize failed\n");
            return FALSE;
        }

        // Handle auf server.dll holen
        HMODULE hSrv = GetModuleHandleA("server.dll");
        if (!hSrv) {
            LOG("[SERVER HOOK] GetModuleHandle server.dll failed\n");
            return FALSE;
        }

        // RVAs relativ zum ImageBase 0x10000000
        uintptr_t base    = (uintptr_t)hSrv;
        FARPROC addrF3720 = (FARPROC)(base + 0x3720);  // FUN_10003720

        // Hooks erzeugen
        MH_STATUS st;
        st = MH_CreateHook(addrF3720, detour_F3720, (LPVOID*)&real_F3720);
        if (st != MH_OK) {
            LOG("[SERVER HOOK] CreateHook F3720 failed: %d\n", st);
            return FALSE;
        }
        // Hooks aktivieren
        if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
            LOG("[SERVER HOOK] EnableHook failed\n");
            return FALSE;
        }
        LOG("[SERVER HOOK] Hooks installed\n");
    }
    else if (reason == DLL_PROCESS_DETACH) {
        LOG("[SERVER HOOK] DLL_PROCESS_DETACH\n");
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        if (logFile != INVALID_HANDLE_VALUE) CloseHandle(logFile);
        DeleteCriticalSection(&logLock);
    }
    return TRUE;
}
