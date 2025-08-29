#include <libmutil/Logger.h>
#include <libmutil/versions.h>

#ifdef USE_SPDLOG
#include <string>
#endif
#include <cstdarg>

namespace libmutil {

#ifdef USE_SPDLOG
std::string mikey_sakke_log_format(const char* format...) {
    /* Get string size */
    va_list org;
    va_start(org, format);
    size_t size = vsnprintf(nullptr, 0, format, org);
    size += 1; // size does not include final \0
    va_end(org);

    /* Allocate a buffer and write into it */
    va_start(org, format);
    char buffer[size];
    vsnprintf(buffer, size, format, org);
    va_end(org);

    return buffer;
}
#else

static struct {
    mikey_sakke_log_level_e level;
    mikey_sakke_log_func_t* log_function;
} mikey_sakke_log_config = {
    .level        = mikey_sakke_log_level_e::MIKEY_SAKKE_LOG_LEVEL_IFO,
    .log_function = nullptr,
};

std::string mikey_sakke_log_level_str(mikey_sakke_log_level_e level) {
    switch (level) {
        case mikey_sakke_log_level_e::MIKEY_SAKKE_LOG_LEVEL_VRB:
            return "verbose";
        case mikey_sakke_log_level_e::MIKEY_SAKKE_LOG_LEVEL_DBG:
            return "debug";
        case mikey_sakke_log_level_e::MIKEY_SAKKE_LOG_LEVEL_NET:
            return "info";
        case mikey_sakke_log_level_e::MIKEY_SAKKE_LOG_LEVEL_IFO:
            return "net";
        case mikey_sakke_log_level_e::MIKEY_SAKKE_LOG_LEVEL_WNG:
            return "warning";
        case mikey_sakke_log_level_e::MIKEY_SAKKE_LOG_LEVEL_ERR:
            return "error";
        case mikey_sakke_log_level_e::MIKEY_SAKKE_LOG_LEVEL_NO:
            return "no logs";
        default:
            return "unsupported";
    }
}

mikey_sakke_log_level_e mikey_sakke_log_level(const std::string& level) {
    if (level == "verbose") {
        return mikey_sakke_log_level_e::MIKEY_SAKKE_LOG_LEVEL_VRB;
    } else if (level == "debug") {
        return mikey_sakke_log_level_e::MIKEY_SAKKE_LOG_LEVEL_DBG;
    } else if (level == "net") {
        return mikey_sakke_log_level_e::MIKEY_SAKKE_LOG_LEVEL_NET;
    } else if (level == "info") {
        return mikey_sakke_log_level_e::MIKEY_SAKKE_LOG_LEVEL_IFO;
    } else if (level == "warning") {
        return mikey_sakke_log_level_e::MIKEY_SAKKE_LOG_LEVEL_WNG;
    } else if (level == "error") {
        return mikey_sakke_log_level_e::MIKEY_SAKKE_LOG_LEVEL_ERR;
    } else {
        return mikey_sakke_log_level_e::MIKEY_SAKKE_LOG_LEVEL_NO;
    }
}

void mikey_sakke_log_set_level(mikey_sakke_log_level_e level) {
    mikey_sakke_log_config.level = level;
    MIKEY_SAKKE_LOGI("Log level set to %s", mikey_sakke_log_level_str(level).c_str());
}

void mikey_sakke_log_set_func(mikey_sakke_log_func_t* func) {
    mikey_sakke_log_config.log_function = func;
    MIKEY_SAKKE_LOGI("sw_mikey_sakke v%s.r%s", mikey_sakke_get_version(), mikey_sakke_get_revision());
}

bool mikey_sakke_should_log(mikey_sakke_log_level_e log_level) {
    return (log_level >= mikey_sakke_log_config.level);
}

void mikey_sakke_log_printf(mikey_sakke_log_level_e log_level, const char* filename, unsigned line, const char* function,
                            const char* format, ...) {
    if (!mikey_sakke_log_config.log_function) {
        return;
    }

    /* Get string size */
    va_list org;
    va_start(org, format);
    size_t size = vsnprintf(NULL, 0, format, org);
    size += 1; // size does not include final \0
    va_end(org);

    /* Allocate a buffer and write into it */
    va_start(org, format);
    char *buffer = (char*)calloc(1, size);
    vsnprintf(buffer, size, format, org);
    va_end(org);

    // TODO add thread id and name to the log
    mikey_sakke_log_config.log_function(log_level, filename, line, function, NULL, 0, buffer);

    free(buffer);
}

void mikey_sakke_log_print(mikey_sakke_log_level_e log_level, const char* filename, unsigned line, const char* function, const char* log) {
    if (!mikey_sakke_log_config.log_function) {
        return;
    }
    mikey_sakke_log_config.log_function(log_level, filename, line, function, NULL, 0, log);
}
#endif // USE_SPDLOG

} // namespace libmutil