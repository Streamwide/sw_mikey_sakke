#ifndef __LOGGER_H__
#define __LOGGER_H__

#include <string>

#ifdef USE_SPDLOG

#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_DEBUG // This must be before the spdlog include
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/spdlog.h>
#endif

namespace libmutil {

enum mikey_sakke_log_level_e {
    MIKEY_SAKKE_LOG_LEVEL_VRB = 0,
    MIKEY_SAKKE_LOG_LEVEL_DBG = 1,
    MIKEY_SAKKE_LOG_LEVEL_NET = 2,
    MIKEY_SAKKE_LOG_LEVEL_IFO = 3,
    MIKEY_SAKKE_LOG_LEVEL_WNG = 4,
    MIKEY_SAKKE_LOG_LEVEL_ERR = 5,
    MIKEY_SAKKE_LOG_LEVEL_NO  = 99,
};

#ifdef USE_SPDLOG

std::string mikey_sakke_log_format(const char* format...);

// There is already a check in spdlog to know if we should log but we can spare ourselves a call
// to mikey_sakke_log_format if we check before we send the log to spdlog
#define MIKEY_SAKKE_LOGV(...)                                                                                                              \
    if (spdlog::should_log(spdlog::level::trace)) {                                                                                        \
        SPDLOG_TRACE(libmutil::mikey_sakke_log_format(__VA_ARGS__));                                                                       \
    }
#define MIKEY_SAKKE_LOGD(...)                                                                                                              \
    if (spdlog::should_log(spdlog::level::debug)) {                                                                                        \
        SPDLOG_DEBUG(libmutil::mikey_sakke_log_format(__VA_ARGS__));                                                                       \
    }
#define MIKEY_SAKKE_LOGI(...)                                                                                                              \
    if (spdlog::should_log(spdlog::level::info)) {                                                                                         \
        SPDLOG_INFO(libmutil::mikey_sakke_log_format(__VA_ARGS__));                                                                        \
    }
#define MIKEY_SAKKE_LOGW(...)                                                                                                              \
    if (spdlog::should_log(spdlog::level::warn)) {                                                                                         \
        SPDLOG_WARN(libmutil::mikey_sakke_log_format(__VA_ARGS__));                                                                        \
    }
#define MIKEY_SAKKE_LOGE(...)                                                                                                              \
    if (spdlog::should_log(spdlog::level::err)) {                                                                                          \
        SPDLOG_ERROR(libmutil::mikey_sakke_log_format(__VA_ARGS__));                                                                       \
    }

#define MIKEY_SAKKE_LOG_SET_LEVEL(level_str) spdlog::set_level(spdlog::level::from_str(level_str))
#define MIKEY_SAKKE_LOG_SET_SINK(path, path_len)                                                                                           \
    if (path && path_len) {                                                                                                                \
        auto logger = spdlog::basic_logger_mt("file_logger", std::string(path, path_len));                                                 \
        spdlog::set_default_logger(logger);                                                                                                \
    } else {                                                                                                                               \
        spdlog::set_default_logger(nullptr);                                                                                               \
    }                                                                                                                                      \
    spdlog::flush_every(std::chrono::seconds(1));

#else

bool mikey_sakke_should_log(mikey_sakke_log_level_e log_level);
void mikey_sakke_log_printf(mikey_sakke_log_level_e log_level, const char* filename, unsigned line, const char* function,
                            const char* format, ...);
void mikey_sakke_log_print(mikey_sakke_log_level_e log_level, const char* filename, unsigned line, const char* function, const char* log);
void mikey_sakke_log_set_level(mikey_sakke_log_level_e level);
std::string             mikey_sakke_log_level_str(mikey_sakke_log_level_e level);
mikey_sakke_log_level_e mikey_sakke_log_level(const std::string& level);
typedef void(mikey_sakke_log_func_t)(int log_level, const char* filename, unsigned line, const char* function, char* thread_name,
                                     long thread_id, const char* log);
void mikey_sakke_log_set_func(mikey_sakke_log_func_t* func);

#define MIKEY_SAKKE_LOG_SET_LEVEL(level_str) libmutil::mikey_sakke_log_set_level(libmutil::mikey_sakke_log_level(level_str))
#define MIKEY_SAKKE_LOG_SET_SINK(path, path_len)

#ifndef MIKEY_SAKKE_LOGV
#define MIKEY_SAKKE_LOGV(...)                                                                                                              \
    if (mikey_sakke_should_log(libmutil::mikey_sakke_log_level_e::MIKEY_SAKKE_LOG_LEVEL_VRB)) {                                            \
        mikey_sakke_log_printf(libmutil::mikey_sakke_log_level_e::MIKEY_SAKKE_LOG_LEVEL_VRB, __FILE__, __LINE__, __FUNCTION__,             \
                               __VA_ARGS__);                                                                                               \
    }
#endif

#ifndef MIKEY_SAKKE_LOGD
#define MIKEY_SAKKE_LOGD(...)                                                                                                              \
    if (mikey_sakke_should_log(libmutil::mikey_sakke_log_level_e::MIKEY_SAKKE_LOG_LEVEL_DBG)) {                                            \
        mikey_sakke_log_printf(libmutil::mikey_sakke_log_level_e::MIKEY_SAKKE_LOG_LEVEL_DBG, __FILE__, __LINE__, __FUNCTION__,             \
                               __VA_ARGS__);                                                                                               \
    }
#endif

#ifndef MIKEY_SAKKE_LOGN
#define MIKEY_SAKKE_LOGN(...)                                                                                                              \
    if (mikey_sakke_should_log(libmutil::mikey_sakke_log_level_e::MIKEY_SAKKE_LOG_LEVEL_NET)) {                                            \
        mikey_sakke_log_printf(libmutil::mikey_sakke_log_level_e::MIKEY_SAKKE_LOG_LEVEL_NET, __FILE__, __LINE__, __FUNCTION__,             \
                               __VA_ARGS__);                                                                                               \
    }
#endif

#ifndef MIKEY_SAKKE_LOGI
#define MIKEY_SAKKE_LOGI(...)                                                                                                              \
    if (mikey_sakke_should_log(libmutil::mikey_sakke_log_level_e::MIKEY_SAKKE_LOG_LEVEL_IFO)) {                                            \
        mikey_sakke_log_printf(libmutil::mikey_sakke_log_level_e::MIKEY_SAKKE_LOG_LEVEL_IFO, __FILE__, __LINE__, __FUNCTION__,             \
                               __VA_ARGS__);                                                                                               \
    }
#endif

#ifndef MIKEY_SAKKE_LOGW
#define MIKEY_SAKKE_LOGW(...)                                                                                                              \
    if (mikey_sakke_should_log(libmutil::mikey_sakke_log_level_e::MIKEY_SAKKE_LOG_LEVEL_WNG)) {                                            \
        mikey_sakke_log_printf(libmutil::mikey_sakke_log_level_e::MIKEY_SAKKE_LOG_LEVEL_WNG, __FILE__, __LINE__, __FUNCTION__,             \
                               __VA_ARGS__);                                                                                               \
    }
#endif

#ifndef MIKEY_SAKKE_LOGE
#define MIKEY_SAKKE_LOGE(...)                                                                                                              \
    if (mikey_sakke_should_log(libmutil::mikey_sakke_log_level_e::MIKEY_SAKKE_LOG_LEVEL_ERR)) {                                            \
        mikey_sakke_log_printf(libmutil::mikey_sakke_log_level_e::MIKEY_SAKKE_LOG_LEVEL_ERR, __FILE__, __LINE__, __FUNCTION__,             \
                               __VA_ARGS__);                                                                                               \
    }
#endif

#endif // USE_SPDLOG

} // namespace libmutil

#endif //__LOGGER_H__