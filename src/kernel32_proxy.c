// hook_kernel32.c
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>

#pragma comment(lib, "kernel32.lib")

// Forward declaration for the real GetTickCount
typedef DWORD (WINAPI *GetTickCount_t)(void);
static GetTickCount_t real_GetTickCount = NULL;

// Function-range markers within server.dll (RVA offsets)
static DWORD fnStart = 0;
static DWORD fnEnd   = 0;

// Load the original kernel32.dll and resolve GetTickCount once
static void load_real_kernel32(void) {
    static BOOL loaded = FALSE;
    if (loaded) return;
    loaded = TRUE;
    wchar_t path[MAX_PATH];
    GetSystemDirectoryW(path, MAX_PATH);
    wcscat_s(path, MAX_PATH, L"\\kernel32.dll");
    HMODULE hMod = LoadLibraryW(path);
    if (hMod) {
        real_GetTickCount = (GetTickCount_t)GetProcAddress(hMod, "GetTickCount");
    }
}

// Hooked export of GetTickCount
__declspec(dllexport)
DWORD WINAPI GetTickCount(void) {
    OutputDebugStringA("-> hooked GetTrickCount was used!\n");
    load_real_kernel32();
    // capture context to inspect return address
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_CONTROL;
    RtlCaptureContext(&ctx);
#ifdef _M_IX86
    DWORD retAddr = ctx.Eip;
#else
    DWORD retAddr = 0; // only x86 supported
#endif
    // if caller in the server function range, suppress timeout
    if (fnStart && fnEnd && retAddr >= fnStart && retAddr < fnEnd) {
        return 0;
    }
    return real_GetTickCount ? real_GetTickCount() : 0;
}

// DllMain: compute fnStart/fnEnd relative to loaded server.dll base
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        OutputDebugStringA("-> hook_kernel32.dll attached\n");
        DisableThreadLibraryCalls(hinst);
        // Compute the full VA range from server.dll base + RVAs
        HMODULE hServer = GetModuleHandleA("server.dll");
        if (hServer) {
            fnStart = (DWORD)hServer + 0x00009AC0u; // RVA_start
            fnEnd   = (DWORD)hServer + 0x00009BDFu; // RVA_end (inclusive RET)
        }
    }
    return TRUE;
}
