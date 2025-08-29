#include <libmutil/Logger.h>
#include <mikeysakkelog4c.h>
#include <stdarg.h>
#include <util/octet-string.h>

#ifndef USE_SPDLOG
bool mikey_sakke_should_log(mikey_sakke_log_level_e log_level) {
    return libmutil::mikey_sakke_should_log((libmutil::mikey_sakke_log_level_e)log_level);
}

void mikey_sakke_log_printf(mikey_sakke_log_level_e log_level, const char* filename, unsigned line, const char* function,
                            const char* format, ...) {
    /* Get string size */
    va_list org;
    va_start(org, format);
    size_t size = vsnprintf(NULL, 0, format, org);
    size += 1; // size does not include final \0
    va_end(org);

    /* Allocate a buffer and write into it */
    va_start(org, format);
    char* buffer = (char*)calloc(1, size);
    vsnprintf(buffer, size, format, org);
    va_end(org);

    // TODO add thread id and name to the log
    libmutil::mikey_sakke_log_print((libmutil::mikey_sakke_log_level_e)log_level, filename, line, function, buffer);
    free(buffer);
}

void mikey_sakke_log_print_hex(enum mikey_sakke_log_level_e log_level, const char* filename, unsigned line, const char* function,
                               uint8_t* bytes, size_t len) {
    OctetString os {len, bytes};
    libmutil::mikey_sakke_log_print((libmutil::mikey_sakke_log_level_e)log_level, filename, line, function, os.translate().c_str());
}

#else

spdlog::level::level_enum to_spdlog_level(mikey_sakke_log_level_e log_level) {
    switch (log_level) {
            // clang-format off
        case MIKEY_SAKKE_LOG_LEVEL_VRB: return spdlog::level::trace;
        case MIKEY_SAKKE_LOG_LEVEL_DBG: return spdlog::level::debug;
        case MIKEY_SAKKE_LOG_LEVEL_NET:
        case MIKEY_SAKKE_LOG_LEVEL_IFO: return spdlog::level::info;
        case MIKEY_SAKKE_LOG_LEVEL_WNG: return spdlog::level::warn;
        case MIKEY_SAKKE_LOG_LEVEL_ERR: return spdlog::level::err;
        case MIKEY_SAKKE_LOG_LEVEL_NO:
        default:                        return spdlog::level::off;
            // clang-format on
    }
    return spdlog::level::off;
}

bool mikey_sakke_should_log(mikey_sakke_log_level_e log_level) {
    return spdlog::should_log(to_spdlog_level(log_level));
}

void mikey_sakke_log_printf(mikey_sakke_log_level_e log_level, const char* filename, unsigned line, const char* function,
                            const char* format, ...) {
    /* Get string size */
    va_list org;
    va_start(org, format);
    size_t size = vsnprintf(NULL, 0, format, org);
    size += 1; // size does not include final \0
    va_end(org);

    /* Allocate a buffer and write into it */
    va_start(org, format);
    char buffer[size];
    vsnprintf(buffer, sizeof(buffer), format, org);
    va_end(org);

    spdlog::default_logger_raw()->log(spdlog::source_loc {filename, (int)line, function}, to_spdlog_level(log_level), buffer);
}

void mikey_sakke_log_print_hex(enum mikey_sakke_log_level_e log_level, const char* filename, unsigned line, const char* function,
                               uint8_t* bytes, size_t len) {
    OctetString os {len, bytes};
    spdlog::default_logger_raw()->log(spdlog::source_loc {filename, (int)line, function}, to_spdlog_level(log_level),
                                      os.translate().c_str());
}

#endif
