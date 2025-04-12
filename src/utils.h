#pragma once

#include <format>
#include <fstream>
#include <iostream>
#include <ostream>
#include <print>

template <class... T>
auto log(std::format_string<T...> fmt, T &&...args) -> void
{
    char tempPath[MAX_PATH]{};
    ::GetEnvironmentVariableA("TEMP", tempPath, MAX_PATH);
    const auto log_path = std::format("{}/log.txt", tempPath);

    if (auto file = std::ofstream{log_path, std::ios::app}; file)
    {
        const auto str = std::format(fmt, std::forward<T>(args)...);
        file << str << '\n';
    }
}

template <class... T>
auto die(std::format_string<T...> fmt, T &&...args) -> void
{
    log(fmt, args...);
    std::println(fmt, args...);
    std::cout << std::flush;

    std::exit(1);
}

template <class... T>
auto ensure(bool cond, std::format_string<T...> fmt, T &&...args) -> void
{
    if (!cond)
    {
        die(fmt, args...);
    }
}
