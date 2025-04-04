#include <Windows.h>

#include "utils.h"

HANDLE(WINAPI *CreateFileA_orig)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE){};

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

    return CreateFileA_orig(
        lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile);
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
                    // thunk_data->u1.Function = reinterpret_cast<::ULONGLONG>(hooked_function);
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

            break;
        }
        case DLL_PROCESS_DETACH: log("DLL_PROCESS_DETACH"); break;
        case DLL_THREAD_ATTACH: log("DLL_THREAD_ATTACH"); break;
        case DLL_THREAD_DETACH: log("DLL_THREAD_DETACH"); break;
    }

    return TRUE;
}

