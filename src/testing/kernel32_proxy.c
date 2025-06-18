#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include "MinHook.h"
#pragma comment(lib, "MinHook.x86.lib")

typedef DWORD (WINAPI *GetTickCount_t)(void);
static GetTickCount_t real_GetTickCount = NULL;

DWORD WINAPI hook_GetTickCount(void) {
    // Capture return address
    CONTEXT ctx = {0}; ctx.ContextFlags = CONTEXT_CONTROL;
    RtlCaptureContext(&ctx);
#ifdef _M_IX86
    DWORD retAddr = ctx.Eip;
#else
    DWORD retAddr = 0;
#endif

    // Log every call
    char dbg[64];
    sprintf(dbg, "[K32TEST] GetTickCount from 0x%08X\n", retAddr);
    OutputDebugStringA(dbg);

    // Always call through
    return real_GetTickCount ? real_GetTickCount() : 0;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID _) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);
        MH_Initialize();
        MH_CreateHookApi(L"kernel32", "GetTickCount",
                        hook_GetTickCount,
                        (void**)&real_GetTickCount);
        MH_EnableHook(MH_ALL_HOOKS);
    }
    else if (reason == DLL_PROCESS_DETACH) {
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
    }
    return TRUE;
}

