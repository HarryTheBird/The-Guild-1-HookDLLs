#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winnt.h>
#pragma comment(lib, "kernel32.lib")

static HMODULE   hRealK32 = NULL;
typedef DWORD     (WINAPI *t_GTC)(void);
typedef ULONGLONG (WINAPI *t_GTC64)(void);
static t_GTC      real_GetTickCount = NULL;
static t_GTC64    real_GetTickCount64 = NULL;
static uintptr_t fnStart = 0, fnEnd = 0;

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID _) {
    if (reason == DLL_PROCESS_ATTACH) {
        wchar_t path[MAX_PATH] = {0};
        GetSystemDirectoryW(path, MAX_PATH);
        wcscat_s(path, MAX_PATH, L"\\kernel32.dll");
        hRealK32 = LoadLibraryW(path);
        if (hRealK32) {
            real_GetTickCount   = (t_GTC)  GetProcAddress(hRealK32, "GetTickCount");
            real_GetTickCount64 = (t_GTC64)GetProcAddress(hRealK32, "GetTickCount64");
        }
        HMODULE hs = GetModuleHandleA("server.dll");
        if (hs) {
            uintptr_t base = (uintptr_t)hs;
            fnStart = base + 0x00009AC0u;
            fnEnd   = base + 0x00009BDFu;
        }
    }
    return TRUE;
}

__declspec(dllexport)
DWORD WINAPI GetTickCount(void) {
    CONTEXT ctx = {0}; ctx.ContextFlags = CONTEXT_CONTROL;
    RtlCaptureContext(&ctx);
    uintptr_t ret =
#ifdef _M_IX86
        ctx.Eip;
#elif defined(_M_X64)
        ctx.Rip;
#else
        0;
#endif
    if (ret >= fnStart && ret < fnEnd) return 0;
    return real_GetTickCount ? real_GetTickCount() : 0;
}

__declspec(dllexport)
ULONGLONG WINAPI GetTickCount64(void) {
    CONTEXT ctx = {0}; ctx.ContextFlags = CONTEXT_CONTROL;
    RtlCaptureContext(&ctx);
    uintptr_t ret =
#ifdef _M_IX86
        ctx.Eip;
#elif defined(_M_X64)
        ctx.Rip;
#else
        0;
#endif
    if (ret >= fnStart && ret < fnEnd) return 0ULL;
    return real_GetTickCount64 ? real_GetTickCount64() : 0ULL;
}