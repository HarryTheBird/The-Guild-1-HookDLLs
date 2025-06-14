#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>    // für SOCKET und WSAEWOULDBLOCK
#include <stdint.h>
#pragma comment(lib, "Ws2_32.lib")

// Funktionspointer
typedef int (WINAPI *recv_t)(SOCKET,char*,int,int);
typedef int (WINAPI *send_t)(SOCKET,const char*,int,int);
typedef uint32_t (WINAPI *t_checksum)(const void*, uint32_t);

static HMODULE    hRealWs       = NULL;
static recv_t     real_recv     = NULL;
static send_t     real_send     = NULL;
static t_checksum real_checksum = NULL;
static uint32_t   seq           = 0;

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID _) {
    if (reason == DLL_PROCESS_ATTACH) {
        // Winsock hooken
        wchar_t path[MAX_PATH] = {0};
        GetSystemDirectoryW(path, MAX_PATH);
        wcscat_s(path, MAX_PATH, L"\ws2_32.dll");
        hRealWs     = LoadLibraryW(path);
        real_recv   = (recv_t)GetProcAddress(hRealWs, "recv");
        real_send   = (send_t)GetProcAddress(hRealWs, "send");
        // Checksum-Routine hooken
        HMODULE hServer = GetModuleHandleA("server.dll");
        real_checksum = (t_checksum)GetProcAddress(hServer, "FUN_100011D0");
    }
    return TRUE;
}

// Hooked recv: liest Header+Payload, prüft CRC via FUN_100011D0, retry bei Fehler
__declspec(dllexport)
int WINAPI recv(SOCKET s, char *buf, int payloadLen, int flags) {
    const int headerSize = 4;    // 4-Byte CRC am Paketanfang
    const int crcOffset  = 0;    // CRC im tmp[0..3]
    int totalLen = headerSize + payloadLen;

    // temporärer Puffer
    char *tmp = (char*)_alloca(totalLen);
    int got = real_recv(s, tmp, totalLen, flags);
    if (got <= 0) return got;
    if (got < headerSize) {
        return recv(s, buf, payloadLen, flags);
    }

    // erwartete CRC (Network-Order)
    uint32_t expected;
    memcpy(&expected, tmp + crcOffset, sizeof(expected));
    expected = ntohl(expected);

    // tatsächliche CRC über Payload
    uint32_t actual = real_checksum(tmp + headerSize, payloadLen);

    if (actual != expected) {
        return recv(s, buf, payloadLen, flags);
    }

    // korrekte Daten kopieren
    memcpy(buf, tmp + headerSize, payloadLen);
    return payloadLen;
}

// Hooked send: Sequenz/Ack & Retry
__declspec(dllexport)
int WINAPI send(SOCKET s, const char *buf, int len, int flags) {
    // Header mit Sequenznummer
    uint32_t net_seq = htonl(seq);
    char header[4]; memcpy(header, &net_seq, sizeof(net_seq));
    int total=0, sent;
    // Header senden
    while (total < sizeof(header)) {
        sent = real_send(s, header+total, sizeof(header)-total, flags);
        if (sent == SOCKET_ERROR && WSAGetLastError()==WSAEWOULDBLOCK) { Sleep(1); continue; }
        if (sent == SOCKET_ERROR) return SOCKET_ERROR;
        total += sent;
    }
    // Payload senden
    total = 0;
    while (total < len) {
        sent = real_send(s, buf+total, len-total, flags);
        if (sent == SOCKET_ERROR && WSAGetLastError()==WSAEWOULDBLOCK) { Sleep(1); continue; }
        if (sent == SOCKET_ERROR) return SOCKET_ERROR;
        total += sent;
    }
    // auf Ack warten
    uint32_t ack;
    int r = real_recv(s, (char*)&ack, sizeof(ack), 0);
    if (r == sizeof(ack) && ntohl(ack) == seq) {
        seq++;
        return len;
    }
    return send(s, buf, len, flags);
}