#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#pragma comment(lib, "Ws2_32.lib")

// Funktionszeiger-Typen
typedef int (WINAPI *recv_t)(SOCKET, char*, int, int);
typedef int (WINAPI *send_t)(SOCKET, const char*, int, int);
static recv_t real_recv = NULL;
static send_t real_send = NULL;

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
    while (st) {
        if (st->s == s) break;
        st = st->next;
    }
    if (!st) {
        st = (SocketState*)malloc(sizeof(SocketState));
        st->s = s;
        st->expectedSeq = 0;
        st->tailBuf = NULL;
        st->tailLen = st->tailSize = 0;
        st->next = stateList;
        stateList = st;
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
        wchar_t path[MAX_PATH] = {0};
        GetSystemDirectoryW(path, MAX_PATH);
        wcscat_s(path, MAX_PATH, L"\ws2_32.dll");
        HMODULE hWs = LoadLibraryW(path);
        real_recv = (recv_t)GetProcAddress(hWs, "recv");
        real_send = (send_t)GetProcAddress(hWs, "send");
    } else if (reason == DLL_PROCESS_DETACH) {
        EnterCriticalSection(&stateLock);
        SocketState *st = stateList;
        while (st) {
            SocketState *next = st->next;
            free(st->tailBuf);
            free(st);
            st = next;
        }
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
    const int headerLen = 8;
    const int csLen     = 4;
    int packetLen = headerLen + len + csLen;
    char *packet = (char*)_alloca(packetLen);
    uint32_t seq;
    // Sequenz atomar inkrementieren
    EnterCriticalSection(&seqLock);
    static uint32_t globalSeq = 0;
    seq = globalSeq++;
    LeaveCriticalSection(&seqLock);
    // Paket zusammenbauen
    *(uint32_t*)(packet + 0) = htonl(seq);
    *(uint32_t*)(packet + 4) = htonl(len);
    memcpy(packet + headerLen, buf, len);
    uint32_t cs = compute_checksum((const uint8_t*)packet, headerLen + len);
    *(uint32_t*)(packet + headerLen + len) = htonl(cs);
    DWORD start = GetTickCount();
    for (int attempt = 0; attempt < MAX_RETRIES; ++attempt) {
        int sent = 0;
        while (sent < packetLen) {
            int ret = real_send(s, packet + sent, packetLen - sent, flags);
            if (ret == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) { Sleep(1); continue; }
            if (ret == SOCKET_ERROR) return SOCKET_ERROR;
            sent += ret;
        }
        // ACK lesen
        uint32_t ack_net; int recvd = 0;
        while (recvd < 4) {
            int r = real_recv(s, (char*)&ack_net + recvd, 4 - recvd, flags);
            if (r <= 0) return SOCKET_ERROR;
            recvd += r;
        }
        if (ntohl(ack_net) == seq) return len;
        if (GetTickCount() - start > SEND_TIMEOUT_MS) break;
        Sleep(10);
    }
    return SOCKET_ERROR; // Timeout oder max Retries
}

// --------------------------------------------------------------------
// Hooked recv: iterative loops, Timeout, Tail-Buffer, ACK/NAK
__declspec(dllexport)
int WINAPI recv(SOCKET s, char *buf, int len, int flags) {
    SocketState *st = getState(s);
    // liefert verbliebene Bytes aus dem Tail-Buffer zuerst
    if (st->tailLen > 0) {
        int c = min(st->tailLen, len);
        memcpy(buf, st->tailBuf, c);
        memmove(st->tailBuf, st->tailBuf + c, st->tailLen - c);
        st->tailLen -= c;
        return c;
    }
    const int headerLen = 8;
    const int csLen     = 4;
    DWORD start = GetTickCount();
    int nakCount = 0;
    while (GetTickCount() - start < RECV_TIMEOUT_MS) {
        // Header lesen
        char hdr[8]; int got = 0;
        while (got < headerLen) {
            int r = real_recv(s, hdr + got, headerLen - got, flags);
            if (r <= 0) return r;
            got += r;
        }
        uint32_t seq = ntohl(*(uint32_t*)hdr);
        uint32_t dataLen = ntohl(*(uint32_t*)(hdr + 4));
        if (dataLen > MAX_PAYLOAD_SIZE) return SOCKET_ERROR;
        int total = dataLen + csLen;
        char *payload = (char*)_alloca(total);
        int recvd = 0;
        while (recvd < total) {
            int r = real_recv(s, payload + recvd, total - recvd, flags);
            if (r <= 0) return r;
            recvd += r;
        }
        uint32_t expected_cs = ntohl(*(uint32_t*)(payload + dataLen));
        uint32_t actual_cs   = compute_checksum((const uint8_t*)hdr, headerLen + dataLen);
        if (actual_cs == expected_cs && seq == st->expectedSeq) {
            // ACK senden
            real_send(s, (char*)hdr, 4, flags);
            int toCopy = min((int)dataLen, len);
            memcpy(buf, payload, toCopy);
            // überschüssige Bytes in Tail-Buffer
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
            return toCopy;
        }
        // NAK senden
        if (nakCount++ < MAX_NAKS) {
            uint32_t nak = htonl(0xFFFFFFFFu);
            real_send(s, (char*)&nak, 4, flags);
            Sleep(1 + (nakCount % 5));
        } else {
            return SOCKET_ERROR;
        }
    }
    return SOCKET_ERROR; // Timeout
}