// server_proxy.c

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <shlwapi.h>
#include "MinHook.h"

#pragma comment(lib, "MinHook.x86.lib")
#pragma comment(lib, "Shlwapi.lib")

static HANDLE logFile = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION logLock;

#define LOG(fmt, ...)                                  \
    do {                                               \
        EnterCriticalSection(&logLock);                \
        if (logFile != INVALID_HANDLE_VALUE) {         \
            char _buf[256];                            \
            int  _len = _snprintf_s(                   \
                _buf, sizeof(_buf), _TRUNCATE,         \
                fmt, __VA_ARGS__                       \
            );                                         \
            DWORD _w;                                  \
            WriteFile(logFile, _buf, _len, &_w, NULL); \
        }                                              \
        LeaveCriticalSection(&logLock);                \
    } while (0)

typedef uint32_t (WINAPI *PFN_CSUM)(void*, uint32_t);
typedef int      (WINAPI *PFN_F3720)(int*, int, int);

static PFN_CSUM  real_CSUM  = NULL;
static PFN_F3720 real_F3720 = NULL;

static uint32_t WINAPI detour_CSUM(void* data, uint32_t len) {
    int32_t r = (int32_t)real_CSUM(data, len);
    LOG("[SERVER HOOK] DETOUR CSUM \n");
    return (r < 0) ? 0u : (uint32_t)r;
}

static int WINAPI detour_F3720(int* ctx, int p2, int p3) {
    int r = real_F3720(ctx, p2, p3);
    LOG("[SERVER HOOK] DETOUR F3720 \n");
    return (r < 0) ? 0 : r;
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        // Logging initialisieren
        InitializeCriticalSection(&logLock);
        {
            wchar_t path[MAX_PATH];
            GetModuleFileNameW(hInst, path, MAX_PATH);
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

        // MinHook
        if (MH_Initialize() != MH_OK) {
            LOG("[SERVER HOOK] MH_Initialize failed\n");
            return FALSE;
        }

        // echte server_base.dll laden
        wchar_t dllPath[MAX_PATH];
        GetModuleFileNameW(hInst, dllPath, MAX_PATH);
        // dllPath == "...\\Europa 1400 The Guild – Gold Edition\\server\\hook_server.dll"

        // Verzeichnis-Teil abschneiden
        PathRemoveFileSpecW(dllPath);
        // dllPath == "...\\Europa 1400 The Guild – Gold Edition\\server"

        // Original-DLL anhängen
        PathAppendW(dllPath, L"server.dll");
        // dllPath == "...\\Europa 1400 The Guild – Gold Edition\\server\\server_base.dll"

        // Jetzt wirklich laden
        HMODULE hSrv = LoadLibraryW(dllPath);
        if (!hSrv) {
            LOG("[SERVER HOOK] failed to LoadLibraryW(%ls): err=%u\n", dllPath, GetLastError());
            return FALSE;
        }

        uintptr_t base   = (uintptr_t)hSrv;
        uintptr_t offCS  = 0x11d0;   // 0x100011d0 - ImageBase
        uintptr_t offF3  = 0x3720;   // 0x10003720 - ImageBase

        MH_STATUS st;
        st = MH_CreateHook((LPVOID)(base + offCS),
                           detour_CSUM, (void**)&real_CSUM);
        if (st != MH_OK) {
            LOG("[SERVER HOOK] CreateHook Csum failed: %d\n", st);
            return FALSE;
        }
        st = MH_CreateHook((LPVOID)(base + offF3),
                           detour_F3720, (void**)&real_F3720);
        if (st != MH_OK) {
            LOG("[SERVER HOOK] CreateHook F3720 failed: %d\n", st);
            return FALSE;
        }
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
        if (logFile != INVALID_HANDLE_VALUE) {
            CloseHandle(logFile);
        }
        DeleteCriticalSection(&logLock);
    }
    return TRUE;
}