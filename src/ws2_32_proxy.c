// ws2_32_proxy_filtered.c
// Inline-Hook DLL via MinHook for ws2_32.dll
// Robust send/recv (seq, checksum, retry, NAK) nur für Aufrufe aus server.dll
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <psapi.h>
#include <shlwapi.h>
#include <malloc.h>   // _alloca
#include <stdint.h>
#include <stdio.h>
#include "MinHook.h"

#define HEADER_LEN 8
#define CS_LEN     4

#pragma comment(lib, "MinHook.x86.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "legacy_stdio_definitions.lib")

// --- Logging ---
static HANDLE logFile = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION logLock;
#define LOG(fmt, ...)                                           \
    do {                                                       \
        EnterCriticalSection(&logLock);                        \
        if (logFile != INVALID_HANDLE_VALUE) {                 \
            char _buf[256];                                    \
            int  _len = _snprintf_s(_buf, sizeof(_buf),        \
                                   _TRUNCATE, fmt, __VA_ARGS__); \
            DWORD _w;                                          \
            WriteFile(logFile, _buf, _len, &_w, NULL);         \
        }                                                      \
        LeaveCriticalSection(&logLock);                        \
    } while (0)

// --- Module range for server.dll ---
static uintptr_t serverBase = 0;
static size_t    serverSize = 0;
static void initServerModuleRange(void) {
    HMODULE hServ = GetModuleHandleA("server.dll");
    if (!hServ) return;
    MODULEINFO mi = {0};
    if (GetModuleInformation(GetCurrentProcess(), hServ, &mi, sizeof(mi))) {
        serverBase = (uintptr_t)mi.lpBaseOfDll;
        serverSize = (size_t)mi.SizeOfImage;
        LOG("[HOOK] server.dll range: 0x%p - 0x%p\n", (void*)serverBase, (void*)(serverBase + serverSize));
    }
}
static BOOL callerInServer(uintptr_t retAddr) {
    return (retAddr >= serverBase && retAddr < serverBase + serverSize);
}

// --- Original function pointers ---
static int (WINAPI *real_recv)(SOCKET, char*, int, int) = NULL;
static int (WINAPI *real_send)(SOCKET, const char*, int, int) = NULL;

// --- Reliable protocol state ---
typedef struct SocketState {
    SOCKET s;
    uint32_t expectedSeq;
    char *tailBuf;
    int tailLen;
    int tailSize;
    struct SocketState *next;
} SocketState;
static SocketState *stateList = NULL;
static CRITICAL_SECTION stateLock;
static CRITICAL_SECTION seqLock;

#define MAX_RETRIES      25
#define SEND_TIMEOUT_MS  10000
#define RECV_TIMEOUT_MS  5000
#define MAX_PAYLOAD_SIZE (10*1024*1024)
#define MAX_NAKS         20

static SocketState* getState(SOCKET s) {
    EnterCriticalSection(&stateLock);
    SocketState *st = stateList;
    while (st && st->s != s) st = st->next;
    if (!st) {
        st = malloc(sizeof(SocketState));
        st->s = s;
        st->expectedSeq = 0;
        st->tailBuf = NULL;
        st->tailLen = st->tailSize = 0;
        st->next = stateList;
        stateList = st;
        LOG("[HOOK] New state socket=%u\n", (unsigned)s);
    }
    LeaveCriticalSection(&stateLock);
    return st;
}
static uint32_t compute_checksum(const uint8_t *data, int len) {
    uint32_t sum = 0;
    for (int i = 0; i < len; ++i) sum += data[i];
    return sum;
}

// --- Hooked recv ---
int WINAPI hook_recv(SOCKET s, char *buf, int len, int flags) {
    // check caller
    CONTEXT ctx = {0}; ctx.ContextFlags = CONTEXT_CONTROL;
    RtlCaptureContext(&ctx);
#ifdef _M_IX86
    uintptr_t ret = ctx.Eip;
#else
    uintptr_t ret = ctx.Rip;
#endif
    if (!callerInServer(ret)) {
        return real_recv(s, buf, len, flags);
    }
    // protocol logic
    SocketState *st = getState(s);
    if (st->tailLen > 0) {
        int c = min(st->tailLen, len);
        memcpy(buf, st->tailBuf, c);
        memmove(st->tailBuf, st->tailBuf + c, st->tailLen - c);
        st->tailLen -= c;
        LOG("[HOOK] tail flush socket=%u len=%d\n", (unsigned)s, c);
        return c;
    }
    LOG("[HOOK] recv begin socket=%u len=%d\n", (unsigned)s, len);
    const int headerLen = 8, csLen = 4;
    DWORD start = GetTickCount();
    int nakCount = 0;
    while (GetTickCount() - start < RECV_TIMEOUT_MS) {
        char hdr[HEADER_LEN];; int got = 0;
        while (got < headerLen) {
            int r = real_recv(s, hdr + got, headerLen - got, flags);
            if (r <= 0) return SOCKET_ERROR;
            got += r;
        }
        uint32_t seq = ntohl(*(uint32_t*)hdr);
        uint32_t dataLen = ntohl(*(uint32_t*)(hdr + 4));
        if (dataLen > MAX_PAYLOAD_SIZE) return SOCKET_ERROR;
        int packetLen = dataLen + csLen;
        char *payload = _alloca(packetLen);
        int recvd = 0;
        while (recvd < packetLen) {
            int r = real_recv(s, payload + recvd, packetLen - recvd, flags);
            if (r <= 0) return SOCKET_ERROR;
            recvd += r;
        }
        uint32_t exp_cs = ntohl(*(uint32_t*)(payload + dataLen));
        uint32_t act_cs = compute_checksum((uint8_t*)hdr, headerLen + dataLen);
        LOG("[HOOK] recv seq=%u len=%u cs_rcv=0x%08X cs_calc=0x%08X\n",
            seq, dataLen, exp_cs, act_cs);
        if (exp_cs == act_cs && seq == st->expectedSeq) {
            real_send(s, hdr, 4, flags); // ACK
            int toCopy = min((int)dataLen, len);
            memcpy(buf, payload, toCopy);
            if (dataLen > (uint32_t)toCopy) {
                int rem = dataLen - toCopy;
                if (st->tailSize < rem) {
                    st->tailBuf = realloc(st->tailBuf, rem);
                    st->tailSize = rem;
                }
                memcpy(st->tailBuf, payload + toCopy, rem);
                st->tailLen = rem;
            }
            st->expectedSeq++;
            LOG("[HOOK] recv OK seq=%u copy=%d\n", seq, toCopy);
            return toCopy;
        }
        if (nakCount < MAX_NAKS) {
            uint32_t nak = htonl(0xFFFFFFFFu);
            real_send(s, (char*)&nak, 4, flags);
            nakCount++;
            LOG("[HOOK] sent NAK=%d seq=%u\n", nakCount, seq);
            Sleep(1 + (nakCount % 5));
        } else {
            LOG("[HOOK] max NAKs reached seq=%u\n", seq);
            return SOCKET_ERROR;
        }
    }
    LOG("[HOOK] recv timeout socket=%u\n", (unsigned)s);
    return SOCKET_ERROR;
}

// --- Hooked send ---
int WINAPI hook_send(SOCKET s, const char *buf, int len, int flags) {
    // check caller
    CONTEXT ctx = {0}; ctx.ContextFlags = CONTEXT_CONTROL;
    RtlCaptureContext(&ctx);
#ifdef _M_IX86
    uintptr_t ret = ctx.Eip;
#else
    uintptr_t ret = ctx.Rip;
#endif
    if (!callerInServer(ret)) {
        return real_send(s, buf, len, flags);
    }
    LOG("[HOOK] send begin socket=%u len=%d flags=0x%X\n", (unsigned)s, len, flags);
    const int headerLen = 8, csLen = 4;
    int packetLen = headerLen + len + csLen;
    char *packet = _alloca(packetLen);
    uint32_t seq;
    EnterCriticalSection(&seqLock);
    static uint32_t globalSeq = 0;
    seq = globalSeq++;
    LeaveCriticalSection(&seqLock);
    *(uint32_t*)(packet)     = htonl(seq);
    *(uint32_t*)(packet + 4) = htonl(len);
    memcpy(packet + headerLen, buf, len);
    uint32_t cs = compute_checksum((uint8_t*)packet, headerLen + len);
    *(uint32_t*)(packet + headerLen + len) = htonl(cs);
    LOG("[HOOK] send seq=%u len=%d cs=0x%08X\n", seq, len, cs);
    DWORD start = GetTickCount();
    for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
        int sent = 0;
        while (sent < packetLen) {
            int r = real_send(s, packet + sent, packetLen - sent, flags);
            if (r == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
                Sleep(1); continue;
            }
            if (r == SOCKET_ERROR) {
                LOG("[HOOK] send error WSA=%d\n", WSAGetLastError());
                return SOCKET_ERROR;
            }
            sent += r;
        }
        LOG("[HOOK] send attempt=%d seq=%u\n", attempt, seq);
        uint32_t ack_net=0; int recvd=0;
        while (recvd < 4) {
            int r=real_recv(s, (char*)&ack_net + recvd, 4-recvd, flags);
            if (r <= 0) return SOCKET_ERROR;
            recvd += r;
        }
        uint32_t ack = ntohl(ack_net);
        LOG("[HOOK] recv ACK=%u expected=%u\n", ack, seq);
        if (ack == seq) return len;
        if (GetTickCount()-start > SEND_TIMEOUT_MS) {
            LOG("[HOOK] send timeout seq=%u\n", seq);
            return SOCKET_ERROR;
        }
        Sleep(10);
    }
    LOG("[HOOK] send max retries seq=%u\n", seq);
    return SOCKET_ERROR;
}

// --- DllMain ---
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID _) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);
        InitializeCriticalSection(&stateLock);
        InitializeCriticalSection(&seqLock);
        InitializeCriticalSection(&logLock);
        // open log
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(hinst, path, MAX_PATH);
        PathRemoveFileSpecW(path);
        wcscat_s(path, MAX_PATH, L"\\hook.log");
        logFile = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ,
                              NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (logFile!=INVALID_HANDLE_VALUE) {
            SetFilePointer(logFile, 0, NULL, FILE_END);
            LOG("[HOOK] ATTACH -> %ls\n", path);
        }
        initServerModuleRange();
        HMODULE hWs = LoadLibraryW(L"ws2_32.dll");
        real_recv = (void*)GetProcAddress(hWs, "recv");
        real_send = (void*)GetProcAddress(hWs, "send");
        MH_Initialize();
        MH_CreateHookApi(L"ws2_32","recv",hook_recv,(void**)&real_recv);
        MH_CreateHookApi(L"ws2_32","send",hook_send,(void**)&real_send);
        MH_EnableHook(MH_ALL_HOOKS);
    } else if (reason == DLL_PROCESS_DETACH) {
        LOG("[HOOK] DETACH\n");
        if (logFile!=INVALID_HANDLE_VALUE) CloseHandle(logFile);
        DeleteCriticalSection(&logLock);
        DeleteCriticalSection(&stateLock);
        DeleteCriticalSection(&seqLock);
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
    }
    return TRUE;
}
