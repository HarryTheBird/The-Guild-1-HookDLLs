#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include "MinHook.h"
#pragma comment(lib, "MinHook.x86.lib")
#pragma comment(lib, "Ws2_32.lib")

typedef int (WINAPI *recv_t)(SOCKET, char*, int, int);
typedef int (WINAPI *send_t)(SOCKET, const char*, int, int);
static recv_t real_recv = NULL;
static send_t real_send = NULL;

// Einfacher Wrapper: nur Loggen, dann 1:1 weiterleiten
int WINAPI hook_recv(SOCKET s, char *buf, int len, int flags) {
    char dbg[64];
    wsprintfA(dbg, "[WSTEST] recv(s=%u,len=%d)\n", (unsigned)s, len);
    OutputDebugStringA(dbg);
    return real_recv ? real_recv(s, buf, len, flags) : SOCKET_ERROR;
}

int WINAPI hook_send(SOCKET s, const char *buf, int len, int flags) {
    char dbg[64];
    wsprintfA(dbg, "[WSTEST] send(s=%u,len=%d)\n", (unsigned)s, len);
    OutputDebugStringA(dbg);
    return real_send ? real_send(s, buf, len, flags) : SOCKET_ERROR;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID _) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);
        MH_Initialize();
        MH_CreateHookApi(L"ws2_32", "recv", hook_recv, (void**)&real_recv);
        MH_CreateHookApi(L"ws2_32", "send", hook_send, (void**)&real_send);
        MH_EnableHook(MH_ALL_HOOKS);
    } else if (reason == DLL_PROCESS_DETACH) {
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
    }
    return TRUE;
}