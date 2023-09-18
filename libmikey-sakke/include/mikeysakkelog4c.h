#ifndef MIKEYSAKKELOG4C_H
#define MIKEYSAKKELOG4C_H

#include <stdint.h>

#if __cplusplus
extern "C" {
#endif

enum mikey_sakke_log_level_e {
    MIKEY_SAKKE_LOG_LEVEL_VRB = 0,
    MIKEY_SAKKE_LOG_LEVEL_DBG = 1,
    MIKEY_SAKKE_LOG_LEVEL_NET = 2,
    MIKEY_SAKKE_LOG_LEVEL_IFO = 3,
    MIKEY_SAKKE_LOG_LEVEL_WNG = 4,
    MIKEY_SAKKE_LOG_LEVEL_ERR = 5,
    MIKEY_SAKKE_LOG_LEVEL_NO  = 99,
};

bool mikey_sakke_should_log(enum mikey_sakke_log_level_e log_level);

void mikey_sakke_log_printf(enum mikey_sakke_log_level_e log_level, const char* filename, unsigned line, const char* function,
                            const char* format, ...);
void mikey_sakke_log_print_hex(enum mikey_sakke_log_level_e log_level, const char* filename, unsigned line, const char* function,
                               uint8_t* bytes, size_t len);

#define SW_MIKEY_SAKKE_LOGD_HEX(data, len)                                                                                                 \
    if (mikey_sakke_should_log(MIKEY_SAKKE_LOG_LEVEL_DBG)) {                                                                               \
        mikey_sakke_log_print_hex(MIKEY_SAKKE_LOG_LEVEL_DBG, __FILE__, __LINE__, __FUNCTION__, (uint8_t*)data, len);                       \
    }

#define SW_MIKEY_SAKKE_LOGV(...)                                                                                                           \
    if (mikey_sakke_should_log(MIKEY_SAKKE_LOG_LEVEL_VRB)) {                                                                               \
        mikey_sakke_log_printf(MIKEY_SAKKE_LOG_LEVEL_VRB, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__);                                  \
    }

#define SW_MIKEY_SAKKE_LOGD(...)                                                                                                           \
    if (mikey_sakke_should_log(MIKEY_SAKKE_LOG_LEVEL_DBG)) {                                                                               \
        mikey_sakke_log_printf(MIKEY_SAKKE_LOG_LEVEL_DBG, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__);                                  \
    }

#define SW_MIKEY_SAKKE_LOGN(...)                                                                                                           \
    if (mikey_sakke_should_log(MIKEY_SAKKE_LOG_LEVEL_NET)) {                                                                               \
        mikey_sakke_log_printf(MIKEY_SAKKE_LOG_LEVEL_NET, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__);                                  \
    }

#define SW_MIKEY_SAKKE_LOGI(...)                                                                                                           \
    if (mikey_sakke_should_log(MIKEY_SAKKE_LOG_LEVEL_IFO)) {                                                                               \
        mikey_sakke_log_printf(MIKEY_SAKKE_LOG_LEVEL_IFO, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__);                                  \
    }

#define SW_MIKEY_SAKKE_LOGW(...)                                                                                                           \
    if (mikey_sakke_should_log(MIKEY_SAKKE_LOG_LEVEL_WNG)) {                                                                               \
        mikey_sakke_log_printf(MIKEY_SAKKE_LOG_LEVEL_WNG, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__);                                  \
    }

#define SW_MIKEY_SAKKE_LOGE(...)                                                                                                           \
    if (mikey_sakke_should_log(MIKEY_SAKKE_LOG_LEVEL_ERR)) {                                                                               \
        mikey_sakke_log_printf(MIKEY_SAKKE_LOG_LEVEL_ERR, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__);                                  \
    }

#if __cplusplus
}
#endif

#endif
