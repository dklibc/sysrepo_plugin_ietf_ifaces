#ifndef _COMMON_H
#define _COMMON_H

#include <syslog.h>
#include <libyang/libyang.h>
#include <sysrepo.h>

#include <libnel/nlroute.h>

#define DEBUG(frmt, ...) syslog(LOG_DEBUG, "%s: "frmt, __func__, ##__VA_ARGS__)
#define ERROR(frmt, ...) syslog(LOG_ERR, "%s: "frmt, __func__, ##__VA_ARGS__)

#endif
