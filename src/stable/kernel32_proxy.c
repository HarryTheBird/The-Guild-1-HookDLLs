#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include "MinHook.h"
#pragma comment(lib, "MinHook.x86.lib")

// Funktionszeiger für das Original
typedef DWORD (WINAPI *GetTickCount_t)(void);
static GetTickCount_t real_GetTickCount = NULL;

// Diese beiden werden jetzt DYNAMIC zur Laufzeit gesetzt!
static DWORD fnStart = 0;
static DWORD fnEnd = 0;

// Wrapper (deine Logik aus dem alten Code)
DWORD WINAPI hook_GetTickCount(void) {
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_CONTROL;
    RtlCaptureContext(&ctx);
#ifdef _M_IX86
    DWORD retAddr = ctx.Eip;
#else
    DWORD retAddr = 0;
#endif
    //if (fnStart && fnEnd && retAddr >= fnStart && retAddr < fnEnd) {
    //    return 0;
    //}
    return real_GetTickCount ? real_GetTickCount() : 0;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID _) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);

        // --------- fnStart/fnEnd beim Laden berechnen (server.dll muss bereits geladen sein) ----------
        HMODULE hServer = GetModuleHandleA("server.dll");
        if (hServer) {
            // Passe die RVAs ggf. an die richtigen Werte deiner Zielfunktion an!
            fnStart = (DWORD)hServer + 0x00009AC0u; // Anfang der relevanten Funktion (RVA!)
            fnEnd   = (DWORD)hServer + 0x00009BDFu; // Ende der relevanten Funktion (inkl. RET) (RVA!)
        }

        MH_Initialize();
        MH_CreateHookApi(L"kernel32", "GetTickCount", hook_GetTickCount, (void**)&real_GetTickCount);
        MH_EnableHook(MH_ALL_HOOKS);
    } else if (reason == DLL_PROCESS_DETACH) {
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
    }
    return TRUE;
}