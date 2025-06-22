#ifndef HOOKLOG_H
#define HOOKLOG_H

#include <windows.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

// Logging variables
static HANDLE logFile = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION logLock;
static UINT32 logLineCount = 0;
#define LOG_MAX_LINES 200

static void ResetLogFile(void) {
    SetFilePointer(logFile, 0, NULL, FILE_BEGIN);
    SetEndOfFile(logFile);
    logLineCount = 0;
}

#ifdef LOG
#undef LOG
#endif
#define LOG(fmt, ...) do { \
    EnterCriticalSection(&logLock); \
    if (logFile != INVALID_HANDLE_VALUE) { \
        if (++logLineCount > LOG_MAX_LINES) { \
            ResetLogFile(); \
        } \
        char _buf[512]; \
        int _len = snprintf(_buf, sizeof(_buf), fmt, ##__VA_ARGS__); \
        DWORD _w; \
        WriteFile(logFile, _buf, _len, &_w, NULL); \
        OutputDebugStringA(_buf); \
    } \
    LeaveCriticalSection(&logLock); \
} while(0)

#ifdef __cplusplus
}
#endif

#endif // HOOKLOG_H 