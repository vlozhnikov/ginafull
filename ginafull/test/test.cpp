#define UNICODE
#include <windows.h>
#include <stdio.h>

void main() {
    HMODULE dll = LoadLibrary(L"D:/temp/full/SecurityBriefs0506/ginafull/bin/ginafull.dll");
    if (!dll) {
        wprintf(L"LoadLibrary failed: %d", GetLastError());
        return;
    }

    FARPROC debugGINA = GetProcAddress(dll, "DebugGINA");
    if (!debugGINA) {
        wprintf(L"GetProcAddress failed: %d", GetLastError());
        return;
    }

    debugGINA();
}