#include <sstream>
#include <stacktrace>

#include <Windows.h>
#include <winternl.h>

#include "ioctl_recorder.h"
#include "ioctl_replayer.h"
#include "utils.h"

HANDLE(WINAPI *CreateFileA_orig)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE){};
HANDLE(WINAPI *CreateFileW_orig)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE){};
UINT(WINAPI *GetDriveTypeA_orig)(LPCSTR){};
UINT(WINAPI *GetDriveTypeW_orig)(LPCWSTR){};
BOOL(WINAPI *ReadFile_orig)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED){};
BOOL(WINAPI *GetVolumeInformationA_orig)(LPCSTR, LPSTR, DWORD, LPDWORD, LPDWORD, LPDWORD, LPSTR, DWORD){};
DWORD(WINAPI *QueryDosDeviceA_orig)(LPCSTR, LPSTR, DWORD){};
DWORD(WINAPI *QueryDosDeviceW_orig)(LPCWSTR, LPWSTR, DWORD){};
DWORD(WINAPI *GetLogicalDrives_orig)(){};
BOOL(WINAPI *GetDiskFreeSpaceA_orig)(LPCSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD){};
BOOL(WINAPI *GetDiskFreeSpaceW_orig)(LPCWSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD){};
BOOL(WINAPI *DeviceIoControl_orig)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED){};
HANDLE(WINAPI *FindFirstVolumeA_orig)(LPSTR, DWORD){};
HANDLE(WINAPI *FindFirstVolumeW_orig)(LPWSTR, DWORD){};
DWORD(WINAPI *GetFileAttributesA_orig)(LPCSTR){};
DWORD(WINAPI *GetFileAttributesW_orig)(LPCWSTR){};
BOOL(WINAPI *IsDebuggerPresent_orig)(VOID){};
BOOL(WINAPI *ReadProcessMemory_orig)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T *){};
BOOL(WINAPI *WriteProcessMemory_orig)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *){};
UINT(WINAPI *GetProfileIntA_orig)(LPCSTR, LPCSTR, UINT){};
void(WINAPI *ExitProcess_orig)(UINT){};
BOOL(WINAPI *TerminateProcess_orig)(HANDLE, UINT){};
BOOL(WINAPI *CreateProcessA_orig)(
    LPCSTR,
    LPSTR,
    LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES,
    BOOL,
    DWORD,
    LPVOID,
    LPCSTR,
    LPSTARTUPINFOA,
    LPPROCESS_INFORMATION){};

static auto g_disable_logging = false;

auto wide_str_to_narrow_str(const std::wstring &wstr) -> std::string
{
    auto len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    auto str = std::string(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, str.data(), len, nullptr, nullptr);
    return str;
}

auto prepare_ioctl_response(std::uint32_t *out_buffer, std::uint32_t val1, std::uint32_t val2) -> void
{
    const auto *kernel_tick_ptr = reinterpret_cast<std::uint32_t *volatile>(0x7ffe0320);
    const auto kernel_tick = *kernel_tick_ptr;

    const auto seed = 0xf367ac7f;
    auto tmp = seed;
    std::uint32_t test_buffer[4]{};

    test_buffer[0] = kernel_tick;

    for (auto i = 3u; i > 0; --i)
    {
        tmp = tmp * -0xd5acb1b + 0x361962e9;
        test_buffer[i] = tmp;
        test_buffer[0] ^= tmp;
    }

    out_buffer[0] = 0x4;
    out_buffer[1] = 0x3;
    out_buffer[2] = 0x56;
    out_buffer[3] = test_buffer[0];
    out_buffer[4] = test_buffer[1];
    out_buffer[5] = test_buffer[2];
    out_buffer[6] = test_buffer[3];
    out_buffer[0x40c / 4] = val1;
    out_buffer[0x410 / 4] = val2;
}

BOOL WINAPI CreateProcessA_hook(
    LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
    log("CreateProcessA called with application name: {} | command line: {}", lpApplicationName, lpCommandLine);

    auto res = CreateProcessA_orig(
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation);

    log("\tCreateProcessA result: {}", res);

    return res;
}

BOOL WINAPI IsDebuggerPresent_hook()
{
    log("IsDebuggerPresent called");

    return FALSE;
}

BOOL WINAPI TerminateProcess_hook(HANDLE hProcess, UINT uExitCode)
{
    log("TerminateProcess called with process: {} | exit code: {}", hProcess, uExitCode);

    ::MessageBeep(0x0);
    ::Sleep(10000);
    ::MessageBeep(0x0);

    log("resuming");

    return TerminateProcess_orig(hProcess, uExitCode);
}

void WINAPI ExitProcess_hook(UINT uExitCode)
{
    log("ExitProcess called with exit code: {}", uExitCode);

    ::Sleep(5000);

    ExitProcess_orig(uExitCode);
}

UINT WINAPI GetProfileIntA_hook(LPCSTR lpAppName, LPCSTR lpKeyName, INT nDefault)
{
    log("GetProfileIntA called with app name: {} | key name: {} | default: {}", lpAppName, lpKeyName, nDefault);
    const auto res = GetProfileIntA_orig(lpAppName, lpKeyName, nDefault);

    log("\tGetProfileIntA result: {}", res);

    return res;
}

BOOL WINAPI ReadProcessMemory_hook(
    HANDLE hProcess,
    LPCVOID lpBaseAddress,
    LPVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T *lpNumberOfBytesRead)
{
    log("ReadProcessMemory called with process: {} | address: {} | size: {}", hProcess, lpBaseAddress, nSize);

    auto res = ReadProcessMemory_orig(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);

    if (res && hProcess == ::GetCurrentProcess())
    {
        const auto *patch_addr = reinterpret_cast<void *>(0x0040aa56);
        if (patch_addr > lpBaseAddress &&
            patch_addr < reinterpret_cast<const void *>(reinterpret_cast<const std::uint8_t *>(lpBaseAddress) + nSize))
        {
            const auto offset = reinterpret_cast<const std::uint8_t *>(patch_addr) -
                                reinterpret_cast<const std::uint8_t *>(lpBaseAddress);
            log("patch address {} is within the read range, undoing patch {}", patch_addr, offset);
            reinterpret_cast<std::uint8_t *>(lpBuffer)[offset] = 0x67;

            auto strm = std::stringstream{};
            const auto *byte = reinterpret_cast<const BYTE *>(lpBuffer);

            for (auto i = 0u; i < nSize; ++i)
            {
                strm << std::format("{:02x} ", byte[i]);
            }

            const auto bytes_str = strm.str();
            log("ReadProcessMemory buffer: {} | {}", bytes_str, nSize);
        }
    }

    log("\tReadProcessMemory result: {}", res);

    return res;
}

BOOL WINAPI WriteProcessMemory_hook(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T *lpNumberOfBytesWritten)
{
    log("WriteProcessMemory called with process: {} | address: {} | size: {}", hProcess, lpBaseAddress, nSize);

    auto res = WriteProcessMemory_orig(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    log("\tWriteProcessMemory result: {}", res);

    return res;
}

HANDLE WINAPI CreateFileA_hook(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile)
{
    log("CreateFileA called with filename: {}", lpFileName);

    auto res = reinterpret_cast<::HANDLE>(0x1234);

    if (std::string_view{lpFileName}.contains("SecDrv") || std::string_view{lpFileName}.contains("Secdrv"))
    {
        log("CreateFileA called with secdrv.sys");
    }
    else
    {
        if (std::string_view{lpFileName}.contains("win.ini"))
        {
            ::MessageBeep(0x0);
            ::Sleep(10000);
            ::MessageBeep(0x0);
        }

        res = CreateFileA_orig(
            lpFileName,
            dwDesiredAccess,
            dwShareMode,
            lpSecurityAttributes,
            dwCreationDisposition,
            dwFlagsAndAttributes,
            hTemplateFile);
    }

    log("\tCreateFileA result: {}", res);

    return res;
}

HANDLE WINAPI CreateFileW_hook(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile)
{
    auto res = reinterpret_cast<::HANDLE>(0x1234);

    const auto narrow_str = wide_str_to_narrow_str(lpFileName);
    if (!narrow_str.contains("log.txt"))
    {
        if (!g_disable_logging)
        {
            log("CreateFileW called with filename: {}", narrow_str);
        }
    }

    if (std::wstring_view{lpFileName}.contains(L"SecDrv"))
    {
        if (!g_disable_logging)
        {
            log("CreateFileW called with secdrv.sys");
        }
    }
    else
    {
        res = CreateFileW_orig(
            lpFileName,
            dwDesiredAccess,
            dwShareMode,
            lpSecurityAttributes,
            dwCreationDisposition,
            dwFlagsAndAttributes,
            hTemplateFile);

        if (!narrow_str.contains("log.txt"))
        {
            if (!g_disable_logging)
            {
                log("\tCreateFileW result: {}", res);
            }
        }
    }

    return res;
}

auto WINAPI DeviceIoControl_hook(
    HANDLE hDevice,
    DWORD dwIoControlCode,
    LPVOID lpInBuffer,
    DWORD nInBufferSize,
    LPVOID lpOutBuffer,
    DWORD nOutBufferSize,
    LPDWORD lpBytesReturned,
    LPOVERLAPPED lpOverlapped) -> BOOL
{
    static auto counter = 0u;
    ++counter;

    if (lpInBuffer && nInBufferSize > 0)
    {
        auto strm = std::stringstream{};
        const auto *byte = reinterpret_cast<const BYTE *>(lpInBuffer);

        for (auto i = 0u; i < nInBufferSize; ++i)
        {
            strm << std::format("{:02x} ", byte[i]);
        }

        const auto bytes_str = strm.str();
        log("DeviceIoControl called with device: {} | {:#x} | buffer: {} {}",
            hDevice,
            dwIoControlCode,
            bytes_str,
            counter);
    }
    else
    {
        log("DeviceIoControl called with device: {} | {:#x} | buffer: {} {}",
            hDevice,
            dwIoControlCode,
            "NULL",
            counter);
    }

    auto res = BOOL{1};
    auto call_orig = true;

    if (dwIoControlCode == 0xef002407)
    {
        log("handling secdrv ioctol");
        auto *out_buffer = reinterpret_cast<std::uint32_t *>(lpOutBuffer);
        auto *in_buffer = reinterpret_cast<std::uint32_t *>(lpInBuffer);
        const auto *in_buffer_check =
            reinterpret_cast<std::uint32_t *>(reinterpret_cast<std::uint8_t *>(lpInBuffer) + 0x414);

        switch (reinterpret_cast<std::uint8_t *>(lpInBuffer)[0xc])
        {
            case 0x3c:
            {
                log("secdrv ioctl: 0x3c");
                prepare_ioctl_response(out_buffer, 0x4, 0x400);
                call_orig = false;

                break;
            }
            case 0x3d:
            {
                log("secdrv ioctl: 0x3d");
                prepare_ioctl_response(out_buffer, 0x4, 0x2c8);
                call_orig = false;

                break;
            }
            case 0x3e:
            {
                log("secdrv ioctl: 0x3e");
                prepare_ioctl_response(out_buffer, 0x4, 0x5278d11b);
                call_orig = false;

                break;
            }
            case 0x3f:
            {
                log("secdrv ioctl: 0x3f");

                if (in_buffer_check[0] < 0x61)
                {
                    prepare_ioctl_response(out_buffer, 0x4, 0x0);
                }
                else
                {
                    log("failed some check, returning 0");
                    res = 0;
                }

                call_orig = false;

                break;
            }
            case 0x41:
            {
                log("secdrv ioctl: 0x41");

                if (in_buffer_check[0] != 0)
                {
                    prepare_ioctl_response(out_buffer, 0x4, 0x0);
                }
                else
                {
                    log("failed some check, returning 0");
                    res = 0;
                }

                call_orig = false;

                break;
            }
            case 0x43:
            {
                log("secdrv ioctl: 0x43");

                if ((in_buffer_check[1] < 8) && (in_buffer_check[0] == 0x98A64100) && (in_buffer_check[1] != 4))
                {
                    prepare_ioctl_response(out_buffer, 0x4, 0x0);
                }
                else
                {
                    log("failed some check, returning 0");
                    res = 0;
                }

                call_orig = false;

                break;
            }
            default:
            {
                log("secdrv ioctl: unknown code: {:#x}", reinterpret_cast<std::uint8_t *>(lpInBuffer)[0xc]);
            }
        }
    }
    else if (dwIoControlCode == 0x24000)
    {
        call_orig = false;
    }

    if (call_orig)
    {
        log("forwarding to original DeviceIoControl {}", counter);

        res = DeviceIoControl_orig(
            hDevice,
            dwIoControlCode,
            lpInBuffer,
            nInBufferSize,
            lpOutBuffer,
            nOutBufferSize,
            lpBytesReturned,
            lpOverlapped);
        log("\tDeviceIoControl result: {} {}", res, counter);

        //     g_disable_logging = true;
        //     static auto recorder = IoctlRecorder{get_temp("all_recording")};
        //     g_disable_logging = false;
        //
        //     recorder.record(
        //         std::span{reinterpret_cast<std::uint8_t *>(lpOutBuffer), static_cast<std::size_t>(nOutBufferSize)},
        //         *lpBytesReturned,
        //         res);
    }

    if (res && lpOutBuffer && nOutBufferSize > 0)
    {
        auto strm = std::stringstream{};
        const auto *byte = reinterpret_cast<const BYTE *>(lpOutBuffer);

        for (auto i = 0u; i < nOutBufferSize; ++i)
        {
            strm << std::format("{:02x} ", byte[i]);
        }

        const auto bytes_str = strm.str();
        log("DeviceIoControl result: {} | buffer: {} {}", res, bytes_str, counter);
    }
    else
    {
        log("{} {} {} {}", res, lpBytesReturned ? *lpBytesReturned : 0, nOutBufferSize, counter);
        log("DeviceIoControl result: {} | buffer: {}", res, counter);
    }

    return res;
}

auto WINAPI GetDriveTypeW_hook(LPCWSTR lpRootPathName) -> UINT
{
    log("GetDriveTypeW called with path: {}", wide_str_to_narrow_str(lpRootPathName));

    auto res = GetDriveTypeW_orig(lpRootPathName);
    log("\tGetDriveTypeW result: {}", res);

    return res;
}

auto WINAPI GetDriveTypeA_hook(LPCSTR lpRootPathName) -> UINT
{
    log("GetDriveTypeA called with path: {}", lpRootPathName);

    auto res = DRIVE_CDROM;

    if (std::string_view{lpRootPathName} == "C:\\DiscNoir\\tin3_dxd.ICD")
    {
        log("icd file");
        ::MessageBeep(0x0);
        ::Sleep(10000);
        ::MessageBeep(0x0);
    }

    // if (!std::string_view{lpRootPathName}.starts_with("X:"))
    // {
    //     log("forwarding to original GetDriveTypeA");
    res = GetDriveTypeA_orig(lpRootPathName);
    // }
    //
    log("\tGetDriveTypeA result: {}", res);

    return res;
}

auto WINAPI ReadFile_hook(
    HANDLE hFile,
    LPVOID lpBuffer,
    DWORD nNumberOfBytesToRead,
    LPDWORD lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped) -> BOOL
{
    if (!g_disable_logging)
    {
        log("ReadFile called with file: {}", hFile);
    }

    auto res = ReadFile_orig(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);

    if (!g_disable_logging)
    {
        log("\tReadFile result: {}", res);
    }

    return res;
}

auto WINAPI GetVolumeInformationA_hook(
    LPCSTR lpRootPathName,
    LPSTR lpVolumeNameBuffer,
    DWORD nVolumeNameSize,
    LPDWORD lpVolumeSerialNumber,
    LPDWORD lpMaximumComponentLength,
    LPDWORD lpFileSystemFlags,
    LPSTR lpFileSystemNameBuffer,
    DWORD nFileSystemNameSize) -> BOOL
{
    log("GetVolumeInformationA called with path: {}", lpRootPathName);

    auto res = GetVolumeInformationA_orig(
        lpRootPathName,
        lpVolumeNameBuffer,
        nVolumeNameSize,
        lpVolumeSerialNumber,
        lpMaximumComponentLength,
        lpFileSystemFlags,
        lpFileSystemNameBuffer,
        nFileSystemNameSize);
    log("\tGetVolumeInformationA result: {}", res);

    return res;
}

auto WINAPI QueryDosDeviceA_hook(LPCSTR lpDeviceName, LPSTR lpTargetPath, DWORD ucchMax) -> DWORD
{
    log("QueryDosDeviceA called with device: {}", lpDeviceName);

    auto res = QueryDosDeviceA_orig(lpDeviceName, lpTargetPath, ucchMax);
    log("\tQueryDosDeviceA result: {}", res);

    return res;
}

auto WINAPI QueryDosDeviceW_hook(LPCWSTR lpDeviceName, LPWSTR lpTargetPath, DWORD ucchMax) -> DWORD
{
    log("QueryDosDeviceW called with device: {}", wide_str_to_narrow_str(lpDeviceName));

    auto res = QueryDosDeviceW_orig(lpDeviceName, lpTargetPath, ucchMax);
    log("\tQueryDosDeviceW result: {}", res);

    return res;
}

auto WINAPI GetLogicalDrives_hook() -> DWORD
{
    log("GetLogicalDrives called");

    auto res = GetLogicalDrives_orig();
    log("\tGetLogicalDrives result: {}", res);

    return res;
}

auto WINAPI GetDiskFreeSpaceA_hook(
    LPCSTR lpRootPathName,
    LPDWORD lpSectorsPerCluster,
    LPDWORD lpBytesPerSector,
    LPDWORD lpNumberOfFreeClusters,
    LPDWORD lpTotalNumberOfClusters) -> BOOL
{
    log("GetDiskFreeSpaceA called with path: {}", lpRootPathName);

    auto res = GetDiskFreeSpaceA_orig(
        lpRootPathName, lpSectorsPerCluster, lpBytesPerSector, lpNumberOfFreeClusters, lpTotalNumberOfClusters);
    log("\tGetDiskFreeSpaceA result: {}", res);

    return res;
}

auto WINAPI GetDiskFreeSpaceW_hook(
    LPCWSTR lpRootPathName,
    LPDWORD lpSectorsPerCluster,
    LPDWORD lpBytesPerSector,
    LPDWORD lpNumberOfFreeClusters,
    LPDWORD lpTotalNumberOfClusters) -> BOOL
{
    log("GetDiskFreeSpaceW called with path: {}", wide_str_to_narrow_str(lpRootPathName));

    auto res = GetDiskFreeSpaceW_orig(
        lpRootPathName, lpSectorsPerCluster, lpBytesPerSector, lpNumberOfFreeClusters, lpTotalNumberOfClusters);
    log("\tGetDiskFreeSpaceW result: {}", res);

    return res;
}

auto WINAPI FindFirstVolumeA_hook(LPSTR lpszVolumeName, DWORD cchBufferLength) -> HANDLE
{
    log("FindFirstVolumeA called with volume: {}", lpszVolumeName);

    auto res = FindFirstVolumeA_orig(lpszVolumeName, cchBufferLength);
    log("\tFindFirstVolumeA result: {}", res);

    return res;
}

auto WINAPI FindFirstVolumeW_hook(LPWSTR lpszVolumeName, DWORD cchBufferLength) -> HANDLE
{
    log("FindFirstVolumeW called with volume: {}", wide_str_to_narrow_str(lpszVolumeName));

    auto res = FindFirstVolumeW_orig(lpszVolumeName, cchBufferLength);
    log("\tFindFirstVolumeW result: {}", res);

    return res;
}

auto WINAPI GetFileAttributesA_hook(LPCSTR lpFileName) -> DWORD
{
    if (lpFileName)
    {
        log("GetFileAttributesA called with filename: {} {}", lpFileName, std::string_view{lpFileName}.length());
    }

    if (std::string_view{lpFileName} == "D:\\00000001.TMP")
    {
        log("routing call to local file");
        lpFileName = "00000001.TMP";
    }

    auto res = GetFileAttributesA_orig(lpFileName);
    log("\tGetFileAttributesA result: {}", res);

    return res;
}

auto WINAPI GetFileAttributesW_hook(LPCWSTR lpFileName) -> DWORD
{
    if (lpFileName)
    {
        log("GetFileAttributesW called with filename: {}", wide_str_to_narrow_str(lpFileName));
    }

    auto res = GetFileAttributesW_orig(lpFileName);
    log("\tGetFileAttributesW result: {}", res);

    return res;
}

auto overwrite_address(void **dst, void *src) -> void
{
    auto old_protect = DWORD{};
    auto res = ::VirtualProtect(dst, sizeof(dst), PAGE_EXECUTE_READWRITE, &old_protect);
    ensure(res != 0, "VirtualProtect failed (first call)");

    log("overwriting address: {} -> {} [{:#x}] ({})", *dst, src, old_protect, res);
    *dst = src;
    log("overwriting address: {} -> {}", *dst, src);

    res = ::VirtualProtect(dst, sizeof(dst), old_protect, &old_protect);
    ensure(res != 0, "VirtualProtect failed (second call)");
}

auto hook_iat(const std::string &dll, const std::string &function, PROC hooked_function, PROC *orig_function) -> bool
{
    HMODULE hModule = GetModuleHandleA(dll.c_str());
    if (!hModule)
    {
        log("failed to get handle for module: {}", dll);
        return false;
    }

    auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE *>(hModule) + dos_header->e_lfanew);

    if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
    {
        log("invalid NT headers");
        return false;
    }

    auto import_directory = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    auto import_descriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        reinterpret_cast<BYTE *>(hModule) + import_directory->VirtualAddress);

    while (import_descriptor->Name)
    {
        auto thunk_data =
            reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<BYTE *>(hModule) + import_descriptor->FirstThunk);
        auto original_thunk_data = reinterpret_cast<PIMAGE_THUNK_DATA>(
            reinterpret_cast<BYTE *>(hModule) + import_descriptor->OriginalFirstThunk);

        while (original_thunk_data->u1.AddressOfData)
        {
            if (original_thunk_data->u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                if (original_thunk_data->u1.Ordinal == reinterpret_cast<ULONG_PTR>(function.c_str()))
                {
                    log("hooking function (ordinal): {}", function);
                    *orig_function = reinterpret_cast<::PROC>(thunk_data->u1.Function);
                    thunk_data->u1.Function = reinterpret_cast<::ULONGLONG>(hooked_function);
                    return true;
                }
            }
            else
            {
                auto import_by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                    reinterpret_cast<BYTE *>(hModule) + original_thunk_data->u1.AddressOfData);
                if (strcmp(reinterpret_cast<const char *>(import_by_name->Name), function.c_str()) == 0)
                {
                    log("hooking function (name): {}", function);
                    *orig_function = reinterpret_cast<::PROC>(thunk_data->u1.Function);
                    overwrite_address(
                        reinterpret_cast<void **>(&thunk_data->u1.Function), reinterpret_cast<void *>(hooked_function));
                    return true;
                }
            }
            ++thunk_data;
            ++original_thunk_data;
        }
        ++import_descriptor;
    }

    log("failed to hook function: {} in module: {}", function, dll);
    return false;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD fdwReason, LPVOID)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
        {
            log("DLL_PROCESS_ATTACH");

            hook_iat(
                "kernel32.dll",
                "CreateFileA",
                reinterpret_cast<::PROC>(CreateFileA_hook),
                reinterpret_cast<::PROC *>(&CreateFileA_orig));

            hook_iat(
                "kernel32.dll",
                "CreateFileW",
                reinterpret_cast<::PROC>(CreateFileW_hook),
                reinterpret_cast<::PROC *>(&CreateFileW_orig));

            hook_iat(
                "kernel32.dll",
                "DeviceIoControl",
                reinterpret_cast<::PROC>(DeviceIoControl_hook),
                reinterpret_cast<::PROC *>(&DeviceIoControl_orig));

            hook_iat(
                "kernel32.dll",
                "GetDriveTypeW",
                reinterpret_cast<::PROC>(GetDriveTypeW_hook),
                reinterpret_cast<::PROC *>(&GetDriveTypeW_orig));

            hook_iat(
                "kernel32.dll",
                "GetDriveTypeA",
                reinterpret_cast<::PROC>(GetDriveTypeA_hook),
                reinterpret_cast<::PROC *>(&GetDriveTypeA_orig));

            hook_iat(
                "kernel32.dll",
                "ReadFile",
                reinterpret_cast<::PROC>(ReadFile_hook),
                reinterpret_cast<::PROC *>(&ReadFile_orig));

            hook_iat(
                "kernel32.dll",
                "GetVolumeInformationA",
                reinterpret_cast<::PROC>(GetVolumeInformationA_hook),
                reinterpret_cast<::PROC *>(&GetVolumeInformationA_orig));

            hook_iat(
                "kernel32.dll",
                "QueryDosDeviceA",
                reinterpret_cast<::PROC>(QueryDosDeviceA_hook),
                reinterpret_cast<::PROC *>(&QueryDosDeviceA_orig));

            hook_iat(
                "kernel32.dll",
                "QueryDosDeviceW",
                reinterpret_cast<::PROC>(QueryDosDeviceW_hook),
                reinterpret_cast<::PROC *>(&QueryDosDeviceW_orig));

            hook_iat(
                "kernel32.dll",
                "GetLogicalDrives",
                reinterpret_cast<::PROC>(GetLogicalDrives_hook),
                reinterpret_cast<::PROC *>(&GetLogicalDrives_orig));

            hook_iat(
                "kernel32.dll",
                "GetDiskFreeSpaceA",
                reinterpret_cast<::PROC>(GetDiskFreeSpaceA_hook),
                reinterpret_cast<::PROC *>(&GetDiskFreeSpaceA_orig));

            hook_iat(
                "kernel32.dll",
                "GetDiskFreeSpaceW",
                reinterpret_cast<::PROC>(GetDiskFreeSpaceW_hook),
                reinterpret_cast<::PROC *>(&GetDiskFreeSpaceW_orig));

            hook_iat(
                "kernel32.dll",
                "FindFirstVolumeA",
                reinterpret_cast<::PROC>(FindFirstVolumeA_hook),
                reinterpret_cast<::PROC *>(&FindFirstVolumeA_orig));

            hook_iat(
                "kernel32.dll",
                "FindFirstVolumeW",
                reinterpret_cast<::PROC>(FindFirstVolumeW_hook),
                reinterpret_cast<::PROC *>(&FindFirstVolumeW_orig));

            hook_iat(
                "kernel32.dll",
                "GetFileAttributesA",
                reinterpret_cast<::PROC>(GetFileAttributesA_hook),
                reinterpret_cast<::PROC *>(&GetFileAttributesA_orig));

            hook_iat(
                "kernel32.dll",
                "GetFileAttributesW",
                reinterpret_cast<::PROC>(GetFileAttributesW_hook),
                reinterpret_cast<::PROC *>(&GetFileAttributesW_orig));

            hook_iat(
                "kernel32.dll",
                "IsDebuggerPresent",
                reinterpret_cast<::PROC>(IsDebuggerPresent_hook),
                reinterpret_cast<::PROC *>(&IsDebuggerPresent_orig));

            hook_iat(
                "kernel32.dll",
                "ReadProcessMemory",
                reinterpret_cast<::PROC>(ReadProcessMemory_hook),
                reinterpret_cast<::PROC *>(&ReadProcessMemory_orig));

            hook_iat(
                "kernel32.dll",
                "ExitProcess",
                reinterpret_cast<::PROC>(ExitProcess_hook),
                reinterpret_cast<::PROC *>(&ExitProcess_orig));

            hook_iat(
                "kernel32.dll",
                "TerminateProcess",
                reinterpret_cast<::PROC>(TerminateProcess_hook),
                reinterpret_cast<::PROC *>(&TerminateProcess_orig));

            std::uint8_t nops[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
            auto old_protect = DWORD{};
            auto res = BOOL{};

            {
                // auto bit_flip = 0xfe;
                // auto *int1_addr = reinterpret_cast<void *>(0x00422166 + 6);
                // auto res = ::VirtualProtect(int1_addr, sizeof(nops), PAGE_EXECUTE_READWRITE, &old_protect);
                // ensure(res != 0, "VirtualProtect failed (int1_addr)");
                // log("overwriting int1_addr with nops: {}", int1_addr);
                // std::memcpy(int1_addr, &bit_flip, sizeof(bit_flip));
                // res = ::VirtualProtect(int1_addr, sizeof(nops), old_protect, &old_protect);
                // ensure(res != 0, "VirtualProtect failed (int1_addr second call)");

                // auto write_mode = std::uint8_t{0x66};
                // auto *write_mode_addr = reinterpret_cast<void *>(0x00040aa56);
                // res = ::VirtualProtect(write_mode_addr, sizeof(write_mode), PAGE_EXECUTE_READWRITE, &old_protect);
                // ensure(res != 0, "VirtualProtect failed (write_mode_addr)");
                // log("overwriting write_mode_addr with: {}", write_mode_addr);
                // std::memcpy(write_mode_addr, &write_mode, sizeof(write_mode));
                // res = ::VirtualProtect(write_mode_addr, sizeof(write_mode), old_protect, &old_protect);
                // ensure(res != 0, "VirtualProtect failed (write_mode_addr second call)");

                //
                // auto *mod_check_addr = reinterpret_cast<void *>(0x000040c1bc);
                // res = ::VirtualProtect(mod_check_addr, sizeof(nops), PAGE_EXECUTE_READWRITE, &old_protect);
                // ensure(res != 0, "VirtualProtect failed (mod_check_addr)");
                // log("overwriting mod_check_addr with nops: {}", mod_check_addr);
                // std::memcpy(mod_check_addr, nops, 2);
                // res = ::VirtualProtect(mod_check_addr, sizeof(nops), old_protect, &old_protect);
                // ensure(res != 0, "VirtualProtect failed (mod_check_addr second call)");

                // auto *patch_detech_addr = reinterpret_cast<void *>(0x000041bc38);
                // auto ret_isntr = std::uint8_t{0xc3};
                // res = ::VirtualProtect(patch_detech_addr, sizeof(ret_isntr), PAGE_EXECUTE_READWRITE, &old_protect);
                // ensure(res != 0, "VirtualProtect failed (patch_detech_addr)");
                // log("overwriting patch_detech_addr with: {}", patch_detech_addr);
                // std::memcpy(patch_detech_addr, &ret_isntr, sizeof(ret_isntr));
                // res = ::VirtualProtect(patch_detech_addr, sizeof(ret_isntr), old_protect, &old_protect);
                // ensure(res != 0, "VirtualProtect failed (patch_detech_addr second call)");

                // std::uint32_t no_debugger_flags[] = {0x422a9d, 0x1, 0x19dba0};
                // auto no_debugger_flag_addr = reinterpret_cast<void *>(0x00428a44);
                // res = ::VirtualProtect(
                //     no_debugger_flag_addr, sizeof(no_debugger_flags), PAGE_EXECUTE_READWRITE, &old_protect);
                // ensure(res != 0, "VirtualProtect failed (no_debugger_flag)");
                // log("overwriting no_debugger_flag");
                //
                // std::memcpy(no_debugger_flag_addr, &no_debugger_flags, sizeof(no_debugger_flags));
                // res = ::VirtualProtect(no_debugger_flag_addr, sizeof(no_debugger_flags), old_protect, &old_protect);
                // ensure(res != 0, "VirtualProtect failed (no_debugger_flag second call)");

                // auto *exception_check_jmp_addr = reinterpret_cast<void *>(0x004221e9);
                // std::uint8_t always_jmp[] = {0xe9, 0xa7, 0x01, 0x00, 0x00};
                // res = ::VirtualProtect(
                //     exception_check_jmp_addr, sizeof(always_jmp), PAGE_EXECUTE_READWRITE, &old_protect);
                // ensure(res != 0, "VirtualProtect failed (exception_check_jmp_addr)");
                // log("overwriting exception_check_jmp_addr with: {}", exception_check_jmp_addr);
                // std::memcpy(exception_check_jmp_addr, always_jmp, sizeof(always_jmp));
                // res = ::VirtualProtect(exception_check_jmp_addr, sizeof(always_jmp), old_protect, &old_protect);
                // ensure(res != 0, "VirtualProtect failed (exception_check_jmp_addr second call)");
            }

            // {
            //     auto peb_check_jmp_addr = reinterpret_cast<void *>(0x000042409a);
            //     res = ::VirtualProtect(peb_check_jmp_addr, sizeof(nops), PAGE_EXECUTE_READWRITE, &old_protect);
            //     ensure(res != 0, "VirtualProtect failed (peb_check_jmp_addr)");
            //     log("overwriting peb_check_jmp_addr with nops: {}", peb_check_jmp_addr);
            //     std::memcpy(peb_check_jmp_addr, nops, sizeof(nops));
            //     res = ::VirtualProtect(peb_check_jmp_addr, sizeof(nops), old_protect, &old_protect);
            //     ensure(res != 0, "VirtualProtect failed (peb_check_jmp_addr second call)");
            // }
            //
            // {
            //     auto peb_debugger_jmp_addr = reinterpret_cast<void *>(0x04212D5);
            //     res = ::VirtualProtect(peb_debugger_jmp_addr, sizeof(nops), PAGE_EXECUTE_READWRITE, &old_protect);
            //     ensure(res != 0, "VirtualProtect failed (peb_debugger_jmp_addr)");
            //     log("overwriting peb_debugger_jmp_addr with nops: {}", peb_debugger_jmp_addr);
            //     std::memcpy(peb_debugger_jmp_addr, nops, sizeof(nops));
            //     res = ::VirtualProtect(peb_debugger_jmp_addr, sizeof(nops), old_protect, &old_protect);
            //     ensure(res != 0, "VirtualProtect failed (peb_debugger_jmp_addr second call)");
            // }
            //
            // {
            //     auto cc_check_addr = reinterpret_cast<void *>(0x0042162f);
            //     auto cc_check_jmp = std::uint8_t{0xeb};
            //     res = ::VirtualProtect(cc_check_addr, sizeof(cc_check_jmp), PAGE_EXECUTE_READWRITE, &old_protect);
            //     ensure(res != 0, "VirtualProtect failed (cc_check_addr)");
            //     log("overwriting cc_check_addr with: {}", cc_check_jmp);
            //     std::memcpy(cc_check_addr, &cc_check_jmp, sizeof(cc_check_jmp));
            //     res = ::VirtualProtect(cc_check_addr, sizeof(cc_check_jmp), old_protect, &old_protect);
            //     ensure(res != 0, "VirtualProtect failed (cc_check_addr second call)");
            // }
            //

            ::Sleep(2000);
            break;
        }
        case DLL_PROCESS_DETACH: log("DLL_PROCESS_DETACH"); break;
        case DLL_THREAD_ATTACH: log("DLL_THREAD_ATTACH"); break;
        case DLL_THREAD_DETACH: log("DLL_THREAD_DETACH"); break;
    }

    return TRUE;
}
