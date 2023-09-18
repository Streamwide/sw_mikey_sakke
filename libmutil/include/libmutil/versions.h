#ifndef LIBMUTIL_VERSIONS_H
#define LIBMUTIL_VERSIONS_H

#include <cstdio>

const char* mikey_sakke_get_version() {
    int  major = 0;
    int  minor = 0;
    char c     = 0;
    if (sscanf(SW_MIKEY_SAKKE_VERSION, "%d.%d%c", &major, &minor, &c) == 2) {
        return SW_MIKEY_SAKKE_VERSION;
    }
    return "99.9";
}

const char* mikey_sakke_get_revision() {
    return SW_MIKEY_SAKKE_REVISION;
}

#endif