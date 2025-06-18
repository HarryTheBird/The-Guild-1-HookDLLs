// injector.c
#include <windows.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

// Check if a string is numeric (PID mode)
bool isNumber(const char *s) {
    if (!s || !*s) return false;
    for (; *s; ++s) {
        if (!isdigit((unsigned char)*s)) return false;
    }
    return true;
}

BOOL InjectDLL(HANDLE hProc, const char* dllPath) {
    size_t len = strlen(dllPath) + 1;
    LPVOID remote = VirtualAllocEx(hProc, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
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
    if (argc < 2) {
        printf("Usage: %s <FullPathGameExe or PID> [HookDLL1] [HookDLL2 ...]\n", argv[0]);
        return 1;
    }

    // Determine if first argument is PID or path
    HANDLE hProc = NULL;
    BOOL started = FALSE;
    if (isNumber(argv[1])) {
        DWORD pid = strtoul(argv[1], NULL, 10);
        hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProc) {
            printf("OpenProcess failed: %u\n", GetLastError());
            return 1;
        }
    } else {
        // Launch new process suspended
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        if (!CreateProcessA(argv[1], NULL, NULL, NULL, FALSE,
                            CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
                            NULL, NULL, &si, &pi)) {
            printf("CreateProcess failed: %u\n", GetLastError());
            return 1;
        }
        hProc = pi.hProcess;
        // Will resume thread after injection
        started = TRUE;
    }

    // Inject each DLL argument
    for (int i = 2; i < argc; i++) {
        printf("Injecting: %s\n", argv[i]);
        if (!InjectDLL(hProc, argv[i])) {
            printf("Injection of %s failed: %u\n", argv[i], GetLastError());
            if (started) TerminateProcess(hProc, 1);
            CloseHandle(hProc);
            return 1;
        }
    }

    // Resume if we created the process
    if (started) {
        // We assume only one primary thread
        ResumeThread((HANDLE) ((uintptr_t)hProc + sizeof(DWORD)));
    }
    CloseHandle(hProc);
    return 0;
}
