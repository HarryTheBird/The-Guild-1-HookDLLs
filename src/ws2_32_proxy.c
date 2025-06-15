#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shlwapi.h>  // für PathRemoveFileSpecW, PathAppendW
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Shlwapi.lib")

// Funktionszeiger-Typen
typedef int (WINAPI *recv_t)(SOCKET, char*, int, int);
typedef int (WINAPI *send_t)(SOCKET, const char*, int, int);
static recv_t real_recv = NULL;
static send_t real_send = NULL;

// File-Logging Handle und Lock
static HANDLE logFile = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION logLock;

// Macro für File-Logging mit optionalen Parametern
#define LOG(fmt, ...)                                      \
    do {                                                   \
        EnterCriticalSection(&logLock);                    \
        if (logFile != INVALID_HANDLE_VALUE) {             \
            char _buf[256];                                \
            int _len = _snprintf_s(_buf, sizeof(_buf),    \
                                   _TRUNCATE, fmt, ##__VA_ARGS__); \
            DWORD _w;                                      \
            WriteFile(logFile, _buf, _len, &_w, NULL);     \
        }                                                  \
        LeaveCriticalSection(&logLock);                    \
    } while(0)

// Pro-Socket-Zustand
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

// Hilfsfunktion: Hole oder lege Zustand an
static SocketState* getState(SOCKET s) {
    EnterCriticalSection(&stateLock);
    SocketState *st = stateList;
    while (st && st->s != s) st = st->next;
    if (!st) {
        st = (SocketState*)malloc(sizeof(SocketState));
        st->s = s;
        st->expectedSeq = 0;
        st->tailBuf = NULL;
        st->tailLen = st->tailSize = 0;
        st->next = stateList;
        stateList = st;
        LOG("[HOOK] New state for socket %u\n", (unsigned)s);
    }
    LeaveCriticalSection(&stateLock);
    return st;
}

// Checksumme über Header+Payload
static uint32_t compute_checksum(const uint8_t *data, int len) {
    uint32_t sum = 0;
    for (int i = 0; i < len; ++i) sum += data[i];
    return sum;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID _) {
    if (reason == DLL_PROCESS_ATTACH) {
        InitializeCriticalSection(&stateLock);
        InitializeCriticalSection(&seqLock);
        InitializeCriticalSection(&logLock);
        // Log-Datei im Modul-Verzeichnis anlegen
        wchar_t logPath[MAX_PATH];
        GetModuleFileNameW(hinst, logPath, MAX_PATH);
        PathRemoveFileSpecW(logPath);
        PathAppendW(logPath, L"\hook.log");
        logFile = CreateFileW(logPath, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                             OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (logFile != INVALID_HANDLE_VALUE) {
            SetFilePointer(logFile, 0, NULL, FILE_END);
            LOG("[HOOK] DLL_PROCESS_ATTACH\n");
        }
        // Winsock original laden
        wchar_t path[MAX_PATH] = {0};
        GetSystemDirectoryW(path, MAX_PATH);
        wcscat_s(path, MAX_PATH, L"\\ws2_32.dll");
        HMODULE hWs = LoadLibraryW(path);
        real_recv = (recv_t)GetProcAddress(hWs, "recv");
        real_send = (send_t)GetProcAddress(hWs, "send");
    } else if (reason == DLL_PROCESS_DETACH) {
        LOG("[HOOK] DLL_PROCESS_DETACH\n");
        if (logFile != INVALID_HANDLE_VALUE) {
            CloseHandle(logFile);
            logFile = INVALID_HANDLE_VALUE;
        }
        DeleteCriticalSection(&logLock);
        // Cleanup states
        EnterCriticalSection(&stateLock);
        SocketState *st = stateList;
        while (st) {
            SocketState *next = st->next;
            free(st->tailBuf);
            free(st);
            st = next;
        }
        stateList = NULL;
        LeaveCriticalSection(&stateLock);
        DeleteCriticalSection(&seqLock);
        DeleteCriticalSection(&stateLock);
    }
    return TRUE;
}

// --------------------------------------------------------------------
// Hooked send: [SEQ(4)][LEN(4)][DATA][CRC(4)] mit Retransmit+Timeout
__declspec(dllexport)
int WINAPI send(SOCKET s, const char *buf, int len, int flags) {
    const int headerLen = 8, csLen = 4;
    int packetLen = headerLen + len + csLen;
    char *packet = (char*)_alloca(packetLen);
    uint32_t seq;
    // Sequenz atomar
    EnterCriticalSection(&seqLock);
    static uint32_t globalSeq = 0;
    seq = globalSeq++;
    LeaveCriticalSection(&seqLock);
    // Paket zusammenbauen
    *(uint32_t*)(packet)        = htonl(seq);
    *(uint32_t*)(packet + 4)    = htonl(len);
    memcpy(packet + headerLen, buf, len);
    uint32_t cs = compute_checksum((uint8_t*)packet, headerLen + len);
    *(uint32_t*)(packet + headerLen + len) = htonl(cs);
    LOG("[HOOK] send seq=%u len=%d cs=0x%08X\n", seq, len, cs);

    DWORD start = GetTickCount();
    for (int attempt = 1; attempt <= MAX_RETRIES; ++attempt) {
        int sent = 0;
        while (sent < packetLen) {
            int ret = real_send(s, packet + sent, packetLen - sent, flags);
            if (ret == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) { Sleep(1); continue; }
            if (ret == SOCKET_ERROR) {
                LOG("[HOOK] send error, WSAErr=%d\n", WSAGetLastError());
                return SOCKET_ERROR;
            }
            sent += ret;
        }
        LOG("[HOOK] send attempt=%d seq=%u\n", attempt, seq);
        // ACK lesen
        uint32_t ack_net = 0;
        int recvd = 0;
        while (recvd < 4) {
            int r = real_recv(s, (char*)&ack_net + recvd, 4 - recvd, flags);
            if (r <= 0) {
                LOG("[HOOK] ack read error, ret=%d\n", r);
                return SOCKET_ERROR;
            }
            recvd += r;
        }
        uint32_t ack = ntohl(ack_net);
        LOG("[HOOK] recv ACK=%u expected=%u\n", ack, seq);
        if (ack == seq) return len;
        if (GetTickCount() - start > SEND_TIMEOUT_MS) {
            LOG("[HOOK] send timeout seq=%u\n", seq);
            return SOCKET_ERROR;
        }
        Sleep(10);
    }
    LOG("[HOOK] send max retries reached seq=%u\n", seq);
    return SOCKET_ERROR;
}

// --------------------------------------------------------------------
// Hooked recv: iterative loops, Timeout, Tail-Buffer, ACK/NAK
__declspec(dllexport)
int WINAPI recv(SOCKET s, char *buf, int len, int flags) {
    SocketState *st = getState(s);
    if (st->tailLen > 0) {
        int c = min(st->tailLen, len);
        memcpy(buf, st->tailBuf, c);
        memmove(st->tailBuf, st->tailBuf + c, st->tailLen - c);
        st->tailLen -= c;
        LOG("[HOOK] tail flush socket=%u len=%d\n", (unsigned)s, c);
        return c;
    }
    const int headerLen = 8, csLen = 4;
    DWORD start = GetTickCount();
    int nakCount = 0;
    while (GetTickCount() - start < RECV_TIMEOUT_MS) {
        char hdr[8];
        int got = 0;
        while (got < headerLen) {
            int r = real_recv(s, hdr + got, headerLen - got, flags);
            if (r <= 0) {
                LOG("[HOOK] recv header error r=%d\n", r);
                return SOCKET_ERROR;
            }
            got += r;
        }
        uint32_t seq    = ntohl(*(uint32_t*)hdr);
        uint32_t dataLen= ntohl(*(uint32_t*)(hdr + 4));
        if (dataLen > MAX_PAYLOAD_SIZE) {
            LOG("[HOOK] recv too large %u\n", dataLen);
            return SOCKET_ERROR;
        }
        int packetLen = dataLen + csLen;
        char *payload = (char*)_alloca(packetLen);
        int recvd = 0;
        while (recvd < packetLen) {
            int r = real_recv(s, payload + recvd, packetLen - recvd, flags);
            if (r <= 0) {
                LOG("[HOOK] recv payload error r=%d\n", r);
                return SOCKET_ERROR;
            }
            recvd += r;
        }
        uint32_t expected_cs = ntohl(*(uint32_t*)(payload + dataLen));
        uint32_t actual_cs   = compute_checksum((const uint8_t*)hdr, headerLen + dataLen);
        LOG("[HOOK] recv seq=%u len=%u cs_rcv=0x%08X cs_calc=0x%08X\n",
            seq, dataLen, expected_cs, actual_cs);
        if (actual_cs == expected_cs && seq == st->expectedSeq) {
            real_send(s, hdr, 4, flags); // ACK
            int toCopy = min((int)dataLen, len);
            memcpy(buf, payload, toCopy);
            if (dataLen > (uint32_t)toCopy) {
                int rem = dataLen - toCopy;
                if (st->tailSize < rem) {
                    st->tailBuf = (char*)realloc(st->tailBuf, rem);
                    st->tailSize = rem;
                }
                memcpy(st->tailBuf, payload + toCopy, rem);
                st->tailLen = rem;
            }
            st->expectedSeq++;
            LOG("[HOOK] recv seq=%u len=%d OK\n", seq, toCopy);
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