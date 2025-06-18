// ws2_32_proxy_filtered_fixed2.c
// Inline-Hook DLL via MinHook for ws2_32.dll
// Robust send/recv (seq, checksum, retry, NAK) only for calls from server.dll
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <psapi.h>
#include <malloc.h>   // _alloca
#include <stdint.h>
#include <stdio.h>
#include "MinHook.h"

#pragma comment(lib, "MinHook.x86.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "legacy_stdio_definitions.lib")

// Constants
#define HEADER_LEN       8   // header size (bytes)
#define CS_LEN           4   // checksum size (bytes)
#define MAX_RETRIES      25
#define SEND_TIMEOUT_MS  10000
#define RECV_TIMEOUT_MS  5000
#define MAX_PAYLOAD_SIZE (10*1024*1024)
#define MAX_NAKS         20

// --- Logging ---
static HANDLE logFile = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION logLock;
#define LOG(fmt, ...)                                           \
    do {                                                       \
        EnterCriticalSection(&logLock);                        \
        if (logFile != INVALID_HANDLE_VALUE) {                 \
            char _buf[256];                                    \
            int  _len = _snprintf_s(                           \
                _buf, sizeof(_buf), _TRUNCATE,                 \
                fmt, __VA_ARGS__                              \
            );                                                 \
            DWORD _w;                                          \
            WriteFile(logFile, _buf, _len, &_w, NULL);         \
        }                                                      \
        LeaveCriticalSection(&logLock);                        \
    } while (0)

// --- Module range for server.dll (lazy init) ---
static uintptr_t serverBase = 0;
static size_t    serverSize = 0;
static void initServerModuleRange(void) {
    if (serverBase) return;
    HMODULE hServ = GetModuleHandleA("server.dll");
    if (!hServ) return;
    MODULEINFO mi = {0};
    if (GetModuleInformation(GetCurrentProcess(), hServ, &mi, sizeof(mi))) {
        serverBase = (uintptr_t)mi.lpBaseOfDll;
        serverSize = (size_t)mi.SizeOfImage;
        LOG("[HOOK] server.dll range: %p - %p\n", (void*)serverBase, (void*)(serverBase + serverSize));
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

static SocketState* getState(SOCKET s) {
    EnterCriticalSection(&stateLock);
    SocketState *st = stateList;
    while (st && st->s != s) st = st->next;
    if (!st) {
        st = malloc(sizeof(*st));
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
    // 1) Lazy init server.dll range
    initServerModuleRange();
    if (!serverBase) return real_recv(s, buf, len, flags);
    
    // 2) Listening-socket skip
    int opt=0, ol=sizeof(opt);
    if (getsockopt(s, SOL_SOCKET, SO_ACCEPTCONN, (char*)&opt, &ol)==0 && opt)
        return real_recv(s, buf, len, flags);
    
    // 3) Caller filter
    CONTEXT ctx={0}; ctx.ContextFlags=CONTEXT_CONTROL;
    RtlCaptureContext(&ctx);
#ifdef _M_IX86
    uintptr_t ret = ctx.Eip;
#else
    uintptr_t ret = ctx.Rip;
#endif
    if (!callerInServer(ret)) return real_recv(s, buf, len, flags);
    
    // 4) Bypass tiny reads
    if ((unsigned)len < HEADER_LEN) {
        LOG("[HOOK] bypass small recv len=%u flags=0x%X\n", (unsigned)len, flags);
        return real_recv(s, buf, len, flags);
    }
    // 5) Clamp negative len
    if (len < 0) {
        LOG("[HOOK] negative recv len=%d -> clamp to 0\n", len);
        len = 0;
    }
    
    LOG("[HOOK] recv begin sock=%u len=%u flags=0x%X\n", (unsigned)s, (unsigned)len, flags);
    
    DWORD start=GetTickCount(); int nak=0;
    while(GetTickCount()-start<RECV_TIMEOUT_MS){
        char hdr[HEADER_LEN]; int got=0;
        while(got<HEADER_LEN){int r=real_recv(s,hdr+got,HEADER_LEN-got,flags); if(r<=0) return SOCKET_ERROR; got+=r;}
        uint32_t seq=ntohl(*(uint32_t*)hdr);
        uint32_t dlen=ntohl(*(uint32_t*)(hdr+4));
        if(dlen>MAX_PAYLOAD_SIZE) return SOCKET_ERROR;
        int pkt=dlen+CS_LEN; char*pl=_alloca(pkt);
        int rec=0; while(rec<pkt){int r=real_recv(s,pl+rec,pkt-rec,flags); if(r<=0) return SOCKET_ERROR; rec+=r;}
        uint32_t exp_c=ntohl(*(uint32_t*)(pl+dlen));
        uint32_t act_c=compute_checksum((uint8_t*)hdr,HEADER_LEN+dlen);
        LOG("[HOOK] recv seq=%u len=%u cs_rcv=0x%08X cs_calc=0x%08X\n", seq, dlen, exp_c, act_c);
        SocketState*st=getState(s);
        if(exp_c==act_c && seq==st->expectedSeq){
            real_send(s,hdr,4,flags);
            int toCopy=min((int)dlen,max(0,len));
            memcpy(buf,pl,toCopy);
            if(dlen>(uint32_t)toCopy){int rem=dlen-toCopy; if(st->tailSize<rem){st->tailBuf=realloc(st->tailBuf,rem);st->tailSize=rem;} memcpy(st->tailBuf,pl+toCopy,rem);st->tailLen=rem;}
            st->expectedSeq++;
            LOG("[HOOK] recv OK seq=%u copy=%d\n", seq, toCopy);
            return toCopy;
        }
        if(nak<MAX_NAKS){uint32_t nk=htonl(0xFFFFFFFFu); real_send(s,(char*)&nk,4,flags); nak++; LOG("[HOOK] sent NAK=%d seq=%u\n", nak, seq); Sleep(1+(nak%5));}
        else{LOG("[HOOK] max NAKs reached seq=%u\n", seq); return SOCKET_ERROR;}
    }
    LOG("[HOOK] recv timeout sock=%u\n", (unsigned)s);
    return SOCKET_ERROR;
}

// --- Hooked send ---
int WINAPI hook_send(SOCKET s, const char *buf, int len, int flags) {
    initServerModuleRange(); if(!serverBase) return real_send(s,buf,len,flags);
    int opt=0,ol=sizeof(opt); if(getsockopt(s,SOL_SOCKET,SO_ACCEPTCONN,(char*)&opt,&ol)==0 && opt) return real_send(s,buf,len,flags);
    CONTEXT ctx={0};ctx.ContextFlags=CONTEXT_CONTROL; RtlCaptureContext(&ctx);
#ifdef _M_IX86
    uintptr_t ret=ctx.Eip;
#else
    uintptr_t ret=ctx.Rip;
#endif
    if(!callerInServer(ret)) return real_send(s,buf,len,flags);
    LOG("[HOOK] send begin sock=%u len=%u flags=0x%X\n",(unsigned)s,(unsigned)len,flags);
    const int h=HEADER_LEN,c=CS_LEN; int pkt=h+len+c; char*p=_alloca(pkt);
    uint32_t seq; EnterCriticalSection(&seqLock); static uint32_t g=0; seq=g++; LeaveCriticalSection(&seqLock);
    *(uint32_t*)p=htonl(seq);*(uint32_t*)(p+4)=htonl(len);memcpy(p+h,buf,len);
    uint32_t cs=compute_checksum((uint8_t*)p,h+len);*(uint32_t*)(p+h+len)=htonl(cs);
    LOG("[HOOK] send seq=%u len=%u cs=0x%08X\n",seq,len,cs);
    DWORD st=GetTickCount();for(int a=1;a<=MAX_RETRIES;a++){int snt=0;while(snt<pkt){int r=real_send(s,p+snt,pkt-snt,flags);if(r==SOCKET_ERROR&&WSAGetLastError()==WSAEWOULDBLOCK){Sleep(1);continue;}if(r==SOCKET_ERROR){LOG("[HOOK] send err WSA=%d\n",WSAGetLastError());return SOCKET_ERROR;}snt+=r;}LOG("[HOOK] send att=%d seq=%u\n",a,seq);uint32_t ackn=0;int rcv=0;while(rcv<4){int r=real_recv(s,(char*)&ackn+rcv,4-rcv,flags);if(r<=0) return SOCKET_ERROR;rcv+=r;}uint32_t ack=ntohl(ackn);LOG("[HOOK] recv ACK=%u exp=%u\n",ack,seq);if(ack==seq) return len;if(GetTickCount()-st> SEND_TIMEOUT_MS){LOG("[HOOK] send to=%u seq=%u\n",SEND_TIMEOUT_MS,seq);return SOCKET_ERROR;}Sleep(10);}LOG("[HOOK] send max seq=%u\n",g);return SOCKET_ERROR;}

// --- DllMain ---
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID _) {
    if(reason==DLL_PROCESS_ATTACH){DisableThreadLibraryCalls(hinst);InitializeCriticalSection(&stateLock);InitializeCriticalSection(&seqLock);InitializeCriticalSection(&logLock);
        // open hook.log next to DLL
        wchar_t path[MAX_PATH];GetModuleFileNameW(hinst,path,MAX_PATH);
        wchar_t*last=wcsrchr(path,L'\\');if(last)*last=L'\0';wcscat_s(path,MAX_PATH,L"\\hook.log");
        logFile=CreateFileW(path,GENERIC_WRITE,FILE_SHARE_READ,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
        if(logFile!=INVALID_HANDLE_VALUE){SetFilePointer(logFile,0,NULL,FILE_END);LOG("[HOOK] ATTACH -> %ls\n",path);}
        initServerModuleRange();HMODULE h=LoadLibraryW(L"ws2_32.dll");real_recv=(void*)GetProcAddress(h,"recv");real_send=(void*)GetProcAddress(h,"send");MH_Initialize();MH_CreateHookApi(L"ws2_32","recv",hook_recv,(void**)&real_recv);MH_CreateHookApi(L"ws2_32","send",hook_send,(void**)&real_send);MH_EnableHook(MH_ALL_HOOKS);
    } else if(reason==DLL_PROCESS_DETACH){LOG("[HOOK] DETACH\n");if(logFile!=INVALID_HANDLE_VALUE)CloseHandle(logFile);DeleteCriticalSection(&logLock);DeleteCriticalSection(&stateLock);DeleteCriticalSection(&seqLock);MH_DisableHook(MH_ALL_HOOKS);MH_Uninitialize();}
    return TRUE;
}
