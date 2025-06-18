#include <windows.h>
#include <stdio.h>

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
    printf("argc = %d\n", argc);
for(int i = 0; i < argc; i++) {
    printf("argv[%d] = \"%s\"\n", i, argv[i]);
}
    if (argc < 3) {
        printf("Usage: %s <FullPathGameExe> <FullPathHookDLL1> [FullPathHookDLL2] [...]\n", argv[0]);
        return 1;
    }

    // 1) Game-Prozess in Suspended State starten
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(
            argv[1], NULL,
            NULL, NULL,
            FALSE,
            CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
            NULL, NULL,
            &si, &pi))
    {
        printf("CreateProcess failed: %u\n", GetLastError());
        return 1;
    }

    // 2) Alle übergebenen DLLs injizieren
    for (int i = 2; i < argc; i++) {
        printf("Injecting: %s\n", argv[i]);
        if (!InjectDLL(pi.hProcess, argv[i])) {
            printf("Injection of %s failed: %u\n", argv[i], GetLastError());
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