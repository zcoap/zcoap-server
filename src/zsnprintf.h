/* 
 * File:   zsnprintf.h
 * Author: Michael Sandstedt
 *
 * An snprintf that doesn't suck.  Fairly full-featured, fast and safe.
 * This was made to work around problems in the Microchip XC16 compiler when
 * targeting DSPIC33 parts.
 *
 * See further comments in zsnprintf.c file.
 *
 * Created on January 1, 2017, 11:38 AM
 */

#ifndef ZSNPRINTF_H
#define	ZSNPRINTF_H

#include <stdarg.h>

size_t zvsnprintf(char *buf, size_t n, const char *fmt, va_list ap);
#ifdef __GNUC__
size_t zsnprintf(char *buf, size_t n, const char *fmt, ...) __attribute__((format (printf, 3, 4)));
#else
size_t zsnprintf(char* buf, size_t n, const char* fmt, ...);
#endif

#endif	/* ZSNPRINTF_H */

