#ifndef FASTSHIELD_LOGGER_HPP
#define FASTSHIELD_LOGGER_HPP

#include <atomic>
#include <iostream>
#include <string>

namespace fastshield {

enum class LogLevel {
    Info,
    Warning,
    Error,
    Debug
};

class Logger {
public:
    static void setVerbose(bool value) {
        verbose().store(value);
    }

    static void log(LogLevel level, const std::string& message) {
        std::ostream& out = (level == LogLevel::Error) ? std::cerr : std::cout;
        out << prefix(level) << message << "\n";
    }

    static void info(const std::string& message) {
        log(LogLevel::Info, message);
    }

    static void warn(const std::string& message) {
        log(LogLevel::Warning, message);
    }

    static void error(const std::string& message) {
        log(LogLevel::Error, message);
    }

    static void debug(const std::string& message) {
        if (verbose().load()) {
            log(LogLevel::Debug, message);
        }
    }

private:
    static std::atomic<bool>& verbose() {
        static std::atomic<bool> value{false};
        return value;
    }

    static const char* prefix(LogLevel level) {
        switch (level) {
        case LogLevel::Info:
            return "[info] ";
        case LogLevel::Warning:
            return "[warn] ";
        case LogLevel::Error:
            return "[error] ";
        case LogLevel::Debug:
            return "[debug] ";
        default:
            return "";
        }
    }
};

} // namespace fastshield

#endif // FASTSHIELD_LOGGER_HPP
