// injector.c
#include <windows.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

// Prüft, ob ein String nur Ziffern enthält
bool isNumber(const char *s) {
    if (!s || !*s) return false;
    for (; *s; ++s) {
        if (!isdigit((unsigned char)*s)) return false;
    }
    return true;
}

BOOL InjectDLL(HANDLE hProc, const char* dllPath) {
    size_t len = strlen(dllPath) + 1;
    LPVOID remote = VirtualAllocEx(hProc, NULL, len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!remote) return FALSE;
    if (!WriteProcessMemory(hProc, remote, dllPath, len, NULL)) return FALSE;
    FARPROC loadLib = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!loadLib) return FALSE;
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)loadLib,
                                        remote, 0, NULL);
    if (!hThread) return FALSE;
    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
    CloseHandle(hThread);
    return TRUE;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        printf("Usage: %s <GameExePath|PID> <HookDLL1> [HookDLL2 ...]\n", argv[0]);
        return 1;
    }

    HANDLE hProc = NULL;
    BOOL launched = FALSE;

    // 1) PID-Mode
    if (isNumber(argv[1])) {
        DWORD pid = strtoul(argv[1], NULL, 10);
        printf("PID-Mode: Opening existing process %u\n", pid);
        hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProc) {
            printf("OpenProcess failed: %u\n", GetLastError());
            return 1;
        }
    }
    // 2) Path-Mode
    else {
        printf("Path-Mode: Launching \"%s\" suspended\n", argv[1]);
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        if (!CreateProcessA(argv[1], NULL, NULL, NULL, FALSE,
                            CREATE_SUSPENDED|CREATE_NEW_CONSOLE,
                            NULL, NULL, &si, &pi)) {
            printf("CreateProcess failed: %u\n", GetLastError());
            return 1;
        }
        hProc    = pi.hProcess;
        launched = TRUE;
    }

    // 3) DLLs injizieren
    for (int i = 2; i < argc; ++i) {
        printf("Injecting: %s\n", argv[i]);
        if (!InjectDLL(hProc, argv[i])) {
            printf("Injection of %s failed: %u\n", argv[i], GetLastError());
            if (launched) TerminateProcess(hProc, 1);
            CloseHandle(hProc);
            return 1;
        }
    }

    // 4) Game-Process weiterspielen lassen
    if (launched) {
        // Die richtige Thread-ID kannst Du per ProcessInformation speichern
        ResumeThread(((PROCESS_INFORMATION*)&hProc)->hThread);
    }
    CloseHandle(hProc);
    return 0;
}