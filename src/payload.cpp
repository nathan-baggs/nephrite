#include <sstream>
#include <stacktrace>

#include <Windows.h>
#include <winternl.h>

#include "utils.h"

HANDLE(WINAPI *CreateFileA_orig)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE){};
HANDLE(WINAPI *CreateFileW_orig)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE){};

BOOL(WINAPI *DeviceIoControl_orig)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED){};

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

    if (std::string_view{lpFileName}.contains("SecDrv"))
    {
        log("CreateFileW called with secdrv.sys");
    }
    else
    {
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
        log("CreateFileW called with filename: {}", narrow_str);
    }

    if (std::wstring_view{lpFileName}.contains(L"SecDrv"))
    {
        log("CreateFileW called with secdrv.sys");
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
            log("\tCreateFileW result: {}", res);
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
    if (lpInBuffer && nInBufferSize > 0)
    {
        auto strm = std::stringstream{};
        const auto *byte = reinterpret_cast<const BYTE *>(lpInBuffer);

        for (auto i = 0u; i < nInBufferSize; ++i)
        {
            strm << std::format("{:02x} ", byte[i]);
        }

        const auto bytes_str = strm.str();
        log("DeviceIoControl called with device: {} | {:#x} | buffer: {}", hDevice, dwIoControlCode, bytes_str);
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
        }
    }

    if (call_orig)
    {
        log("forwarding to original DeviceIoControl");

        res = DeviceIoControl_orig(
            hDevice,
            dwIoControlCode,
            lpInBuffer,
            nInBufferSize,
            lpOutBuffer,
            nOutBufferSize,
            lpBytesReturned,
            lpOverlapped);
    }

    if (res && lpOutBuffer && nOutBufferSize > 0 && lpBytesReturned && *lpBytesReturned > 0)
    {
        log("DeviceIoControl returned {} bytes", *lpBytesReturned);

        auto strm = std::stringstream{};
        const auto *byte = reinterpret_cast<const BYTE *>(lpOutBuffer);

        for (auto i = 0u; i < nOutBufferSize; ++i)
        {
            strm << std::format("{:02x} ", byte[i]);
        }

        const auto bytes_str = strm.str();
        log("DeviceIoControl result: {} | buffer: {}", res, bytes_str);
    }

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

            break;
        }
        case DLL_PROCESS_DETACH: log("DLL_PROCESS_DETACH"); break;
        case DLL_THREAD_ATTACH: log("DLL_THREAD_ATTACH"); break;
        case DLL_THREAD_DETACH: log("DLL_THREAD_DETACH"); break;
    }

    return TRUE;
}
