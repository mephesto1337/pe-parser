#ifndef __CHECK_H__
#define __CHECK_H__

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#define __log_msg(fmt, ...) fprintf(stderr, fmt "\n", ## __VA_ARGS__)
#if defined(DEBUG) && DEBUG > 0
#   define debug(fmt, ...)  __log_msg("\e[0;1m[DEBUG]\e[0m " fmt, ## __VA_ARGS__)
#else
#   define debug(fmt, ...)
#endif
#define error(fmt, ...)     __log_msg("\e[0;1;31m[ERROR]\e[0m" fmt, ## __VA_ARGS__)

#define CHK(expr, cond) \
    do { \
        debug("%s", #expr); \
        if ( (expr) cond ) { \
            error("((%s) %s) at %s:%d", #expr, #cond, __FILE__, __LINE__); \
            goto fail; \
        } \
    } while ( 0 )
#define CHK_NEG(expr)       CHK(expr, < 0L)
#define CHK_NULL(expr)      CHK(expr, == NULL)
#define CHK_MMAP(expr)      CHK(expr, == MAP_FAILED)


#define SAFE_FREE(handle, null_val, func, ...)  \
    do { \
        if ( (handle) != null_val ) { \
            func(handle, ## __VA_ARGS__); \
        } \
        handle = null_val; \
    } while ( 0 )
#define safe_close(fd)          SAFE_FREE(fd, -1, close)
#define safe_munmap(ptr, size)  SAFE_FREE(ptr, MAP_FAILED, munmap, size)
#define safe_free(ptr)          SAFE_FREE(ptr, NULL, free)

#endif // __CHECK_H__
