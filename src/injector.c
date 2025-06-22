// injector.c
#include <windows.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

// Prüft, ob ein String nur Ziffern enthält
static bool isNumber(const char *s) {
    if (!s || !*s) return false;
    for (; *s; ++s) if (!isdigit((unsigned char)*s)) return false;
    return true;
}

// Injiziert eine DLL in den Zielprozess
static BOOL InjectDLL(HANDLE hProc, const char* dllPath) {
    size_t len = strlen(dllPath) + 1;
    LPVOID remote = VirtualAllocEx(hProc, NULL, len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!remote) return FALSE;
    if (!WriteProcessMemory(hProc, remote, dllPath, len, NULL)) {
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        return FALSE;
    }
    FARPROC loadLib = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!loadLib) {
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        return FALSE;
    }
    HANDLE hThread = CreateRemoteThread(
        hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)loadLib,
        remote, 0, NULL
    );
    if (!hThread) {
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        return FALSE;
    }
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
    return TRUE;
}

int main(int argc, char** argv) {
    if (argc < 5) {
        printf("Usage: %s <GameExePath|PID> <server.dll> <hook_server.dll> <hook_ws2_32.dll> <hook_kernel32.dll> [...]\n", argv[0]);
        return 1;
    }

    // argv[2] ist jetzt Deine server.dll
    const char* serverDll = argv[2];

    // 1) PID-Mode oder Path-Mode
    HANDLE hProc   = NULL, hThread = NULL;
    PROCESS_INFORMATION pi = {0};
    BOOL launched = FALSE;

    if (isNumber(argv[1])) {
        DWORD pid = strtoul(argv[1], NULL, 10);
        printf("[Injector] PID-Mode: OpenProcess(%lu)\n", pid);
        hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProc) { printf("  OpenProcess failed: %lu\n", GetLastError()); return 1; }
    } else {
        printf("[Injector] Path-Mode: CreateProcessA(\"%s\") suspended\n", argv[1]);
        STARTUPINFOA si = { sizeof(si) };
        if (!CreateProcessA(
                argv[1], NULL, NULL, NULL, FALSE,
                CREATE_SUSPENDED|CREATE_NEW_CONSOLE,
                NULL, NULL, &si, &pi)) 
        {
            printf("  CreateProcess failed: %lu\n", GetLastError());
            return 1;
        }
        hProc   = pi.hProcess;
        hThread = pi.hThread;
        launched = TRUE;
    }

    // 2) Zuerst server.dll laden
    printf("[Injector] Loading server DLL: %s\n", serverDll);
    if (!InjectDLL(hProc, serverDll)) {
        printf("  Failed to load %s: %lu\n", serverDll, GetLastError());
        goto cleanup;
    }

    // 3) Dann alle weiteren Hook-DLLs ab argv[3]
    for (int i = 3; i < argc; ++i) {
        printf("[Injector] Injecting hook: %s\n", argv[i]);
        if (!InjectDLL(hProc, argv[i])) {
            printf("  Injection of %s failed: %lu\n", argv[i], GetLastError());
            goto cleanup;
        }
    }

    // 4) Im Path-Mode den Haupt-Thread fortsetzen
    if (launched) {
        printf("[Injector] Resuming main thread\n");
        ResumeThread(hThread);
    }

cleanup:
    if (hThread) CloseHandle(hThread);
    if (hProc)   CloseHandle(hProc);
    return 0;
}