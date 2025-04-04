#include <cstring>

#include <windows.h>

#include "utils.h"

auto main() -> int
{
    log("launching game");

    auto si = ::STARTUPINFO{.cb = sizeof(::STARTUPINFO)};
    auto pi = ::PROCESS_INFORMATION{};

    const auto game =
        ::CreateProcessA("bond.exe", nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi);
    ensure(game, "CreateProcess failed");

    const auto remote_buffer = ::VirtualAllocEx(pi.hProcess, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ensure(remote_buffer != nullptr, "VirtualAllocEx failed");

    const auto dll_path = "payload.dll";
    const auto written = ::WriteProcessMemory(pi.hProcess, remote_buffer, dll_path, std::strlen(dll_path), nullptr);
    ensure(written != 0, "WriteProcessMemory failed");

    const auto remote_thread = ::CreateRemoteThread(
        pi.hProcess, nullptr, 0, reinterpret_cast<::LPTHREAD_START_ROUTINE>(::LoadLibraryA), remote_buffer, 0, nullptr);
    ensure(remote_thread != nullptr, "CreateRemoteThread failed");

    ::WaitForSingleObject(remote_thread, INFINITE);

    log("remote thread finished");

    ::ResumeThread(remote_thread);

    log("game process created with pid {}, resuming", pi.dwProcessId);

    ::ResumeThread(pi.hThread);

    return 0;
}
