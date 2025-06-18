#include <windows.h>
#include <stdio.h>
#include <string.h>

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
        printf("Usage: %s <FullPathGameExe>\n", argv[0]);
        return 1;
    }

    // Pfad zur Spiel-EXE
    char* gamePath = argv[1];
    // Verzeichnis extrahieren
    char exeDir[MAX_PATH];
    strcpy_s(exeDir, MAX_PATH, gamePath);
    char* slash = strrchr(exeDir, '\\');
    if (slash) *slash = '\0';

    // Hook-DLLs im Unterordner 'server'
    char dlls[2][MAX_PATH];
    snprintf(dlls[0], MAX_PATH, "%s\\server\\hook_kernel32.dll", exeDir);
    snprintf(dlls[1], MAX_PATH, "%s\\server\\hook_ws2_32.dll", exeDir);

    // Debug-Ausgabe
    printf("Starting: %s\nInjection folder: %s\\server\\\n", gamePath, exeDir);
    for (int i = 0; i < 2; i++) {
        printf("Will inject: %s\n", dlls[i]);
    }

    // 1) Spiel im Suspended-Modus starten
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(gamePath, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
                        NULL, NULL, &si, &pi)) {
        printf("CreateProcess failed: %u\n", GetLastError());
        return 1;
    }

    // 2) Beide DLLs injizieren
    for (int i = 0; i < 2; i++) {
        if (!InjectDLL(pi.hProcess, dlls[i])) {
            printf("Injection of %s failed: %u\n", dlls[i], GetLastError());
            TerminateProcess(pi.hProcess, 1);
            return 1;
        }
    }

    // 3) Prozess fortsetzen
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
