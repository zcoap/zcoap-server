/*
 * File:   zsnprintf.c
 * Author: Michael Sandstedt
 *
 * Created on January 1, 2017, 11:38 AM
 *
 * An snprintf that actually works and won't kill performance.
 *
 * The snprintf that's packaged with v1.24 of Microchip's XC16 compiler is hopelessly
 * broken and does *not* respect the maximum character argument.  It's also dog
 * slow.  To add insult to injury, while it's parsing and printing, it achieves
 * thread safety by disabling interrupts!
 *
 * Needless to say, this is completely unacceptable. So here's a reentrant
 * implementation that actually works and is up to 80x faster!
 *
 * This implementation has some minor limitations:
 *    * the %o (octal) format specifier produces %x output
 *    * the C99 %a/%A format specifiers are interpreted as %e/%E
 *    * %f produces %e output for abs(float) > INT32_MAX
 *    * the '-' flag (left justify) isn't supported
 *    * the '#' alternate form flag isn't supported
 *    * %g/%G aren't guaranteed to produce the most compact output,
 *      and may be printed with trailing zeros
 *    * printed precision for 64 bit doubles can be less the full 53 bits of the
 *      mantissa; some usages will produce output precision capped to 32 bits
 *
 * But in most ways, this implementation is actually *more* feature-rich than
 * the library version.  For instance, the XC16 option to use 32-bit doubles is
 * fully supported, and when selected, there's a significant speedup printing
 * 32-bit floats.  And whereas the XC16 version skips %Lf (long double)
 * arguments completely, this version properly supports them.
 *
 * All in all, this implementation should provide excellent performance, correct
 * operation where critical, and should in general be a much better alternative
 * to the library implementation.
 */

#include <float.h>
#include <limits.h>
#include <math.h>
#include <tgmath.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include "config.h"
#include "zsnprintf.h"

#ifdef USE_ZCOAP_SNPRINTF

#define MAX_WIDTH_SUB_SPEC "0-+ #"MAX_DEC_FMT_I32"."MAX_DEC_FMT_I32"ll"
#define DTOCHAR(_d) ((_d) + '0')
#define XTOCHAR(_x) ((_x) >= 0xA ? (_x) - 0xA + 'A' : DTOCHAR(_x))
#define ARG_SPECIFIED -2
#define PRECISION_UNSPECIFIED -1
#define DEFAULT_PRECISION 4
#define MAX_DEC_FMT_I32 "-2147483648"
#define MAX_DEC_FMT_I16 "-32767"

typedef enum sign_e {
    auto_sign,
    always_sign,
    sign_or_space,
} sign_t;

typedef enum exp_form_e {
    exp_none,
    exp_e,
    exp_E,
} exp_form_t;

typedef struct flags_s {
    unsigned leftAlign : 1;
    unsigned sign : 2;
    unsigned altForm : 1;
    unsigned zeropad : 1;
    unsigned exp : 2;
} fmt_flags_t;

#if (__DBL_MANT_DIG__ != __FLT_MANT_DIG__)
#define zftoa zftoal
#else
#define zftoa zftoaf
#endif

static char *zx16toa(char *buf, uint16_t n, unsigned width, fmt_flags_t flags)
{
    uint8_t d3, d2, d1, d0;
    unsigned first_digit = 0;

    d0 = n & 0xF;
    d1 = (n >> 4) & 0xF; if (d1) { first_digit = 1; }
    d2 = (n >> 8) & 0xF; if (d2) { first_digit = 2; }
    d3 = (n >> 12) & 0xF; if (d3) { first_digit = 3; }

    if (width) {
        // width is 1-based; change to 0-based
        if (width > 3) {
            width = 3;
        } else {
            --width;
        }
        if (flags.zeropad) {
            for (unsigned i = width; i > first_digit; --i) {
                *buf = '0';
                ++buf;
            }
        } else {
            for (unsigned i = width; i > first_digit; --i) {
                *buf = ' ';
                ++buf;
            }
        }
    }

    switch (first_digit) {
        case 3: *buf = XTOCHAR(d3); ++buf;
        case 2: *buf = XTOCHAR(d2); ++buf;
        case 1: *buf = XTOCHAR(d1); ++buf;
    }
    *buf = XTOCHAR(d0); ++buf;
    *buf = '\0';
    return buf;
}

static char *zx32toa(char *buf, uint32_t n, unsigned width, fmt_flags_t flags)
{
    uint8_t d7, d6, d5, d4, d3, d2, d1, d0;
    unsigned first_digit = 0;

    d0 = n & 0xF;
    d1 = (n >> 4) & 0xF; if (d1) { first_digit = 1; }
    d2 = (n >> 8) & 0xF; if (d2) { first_digit = 2; }
    d3 = (n >> 12) & 0xF; if (d3) { first_digit = 3; }
    d4 = (n >> 16) & 0xF; if (d4) { first_digit = 4; }
    d5 = (n >> 20) & 0xF; if (d5) { first_digit = 5; }
    d6 = (n >> 24) & 0xF; if (d6) { first_digit = 6; }
    d7 = (n >> 28) & 0xF; if (d7) { first_digit = 7; }

    if (width) {
        // width is 1-based; change to 0-based
        if (width > 7) {
            width = 7;
        } else {
            --width;
        }
        if (flags.zeropad) {
            for (unsigned i = width; i > first_digit; --i) {
                *buf = '0';
                ++buf;
            }
        } else {
            for (unsigned i = width; i > first_digit; --i) {
                *buf = ' ';
                ++buf;
            }
        }
    }

    switch (first_digit) {
        case 7: *buf = XTOCHAR(d7); ++buf;
        case 6: *buf = XTOCHAR(d6); ++buf;
        case 5: *buf = XTOCHAR(d5); ++buf;
        case 4: *buf = XTOCHAR(d4); ++buf;
        case 3: *buf = XTOCHAR(d3); ++buf;
        case 2: *buf = XTOCHAR(d2); ++buf;
        case 1: *buf = XTOCHAR(d1); ++buf;
    }
    *buf = XTOCHAR(d0); ++buf;
    *buf = '\0';
    return buf;
}

static char *zx64toa(char *buf, uint64_t n, unsigned width, fmt_flags_t flags)
{
    uint8_t d15, d14, d13, d12, d11, d10, d9, d8, d7, d6, d5, d4, d3, d2, d1, d0;
    unsigned first_digit = 0;

    d0 = n & 0xF;
    d1 = (n >> 4) & 0xF; if (d1) { first_digit = 1; }
    d2 = (n >> 8) & 0xF; if (d2) { first_digit = 2; }
    d3 = (n >> 12) & 0xF; if (d3) { first_digit = 3; }
    d4 = (n >> 16) & 0xF; if (d4) { first_digit = 4; }
    d5 = (n >> 20) & 0xF; if (d5) { first_digit = 5; }
    d6 = (n >> 24) & 0xF; if (d6) { first_digit = 6; }
    d7 = (n >> 28) & 0xF; if (d7) { first_digit = 7; }
    d8 = (n >> 32) & 0xF; if (d8) { first_digit = 8; }
    d9 = (n >> 36) & 0xF; if (d9) { first_digit = 9; }
    d10 = (n >> 40) & 0xF; if (d10) { first_digit = 10; }
    d11 = (n >> 44) & 0xF; if (d11) { first_digit = 11; }
    d12 = (n >> 48) & 0xF; if (d12) { first_digit = 12; }
    d13 = (n >> 52) & 0xF; if (d13) { first_digit = 13; }
    d14 = (n >> 56) & 0xF; if (d14) { first_digit = 14; }
    d15 = (n >> 60) & 0xF; if (d15) { first_digit = 15; }

    if (width) {
        // width is 1-based; change to 0-based
        if (width > 15) {
            width = 15;
        } else {
            --width;
        }
        if (flags.zeropad) {
            for (unsigned i = width; i > first_digit; --i) {
                *buf = '0';
                ++buf;
            }
        } else {
            for (unsigned i = width; i > first_digit; --i) {
                *buf = ' ';
                ++buf;
            }
        }
    }

    switch (first_digit) {
        case 15: *buf = XTOCHAR(d15); ++buf;
        case 14: *buf = XTOCHAR(d14); ++buf;
        case 13: *buf = XTOCHAR(d13); ++buf;
        case 12: *buf = XTOCHAR(d12); ++buf;
        case 11: *buf = XTOCHAR(d11); ++buf;
        case 10: *buf = XTOCHAR(d10); ++buf;
        case 9: *buf = XTOCHAR(d9); ++buf;
        case 8: *buf = XTOCHAR(d8); ++buf;
        case 7: *buf = XTOCHAR(d7); ++buf;
        case 6: *buf = XTOCHAR(d6); ++buf;
        case 5: *buf = XTOCHAR(d5); ++buf;
        case 4: *buf = XTOCHAR(d4); ++buf;
        case 3: *buf = XTOCHAR(d3); ++buf;
        case 2: *buf = XTOCHAR(d2); ++buf;
        case 1: *buf = XTOCHAR(d1); ++buf;
    }
    *buf = XTOCHAR(d0); ++buf;
    *buf = '\0';
    return buf;
}

#define addSign(_buf, _n, _flags) ({\
    if (_n < 0) {\
        *_buf = '-';\
        ++_buf;\
    } else if (_flags.sign == always_sign) {\
        *_buf = '+';\
        ++_buf;\
    } else if (_flags.sign == sign_or_space) {\
        *_buf = ' ';\
        ++_buf;\
    }\
})

static char *zi16toa(char *buf, int16_t n, unsigned width, fmt_flags_t flags)
{
    uint8_t d4, d3, d2, d1, q; // yes, 8 bits are enough for these
    uint16_t d0;
    unsigned first_digit = 0;

    uint16_t absn = n < 0 ? -n : n;
    d0 = absn & 0xF;
    d1 = (absn >> 4) & 0xF;
    d2 = (absn >> 8) & 0xF;
    d3 = (absn >> 12) & 0xF;

    d0 = 6*(d3 + d2 + d1) + d0;
    q = d0 / 10;
    d0 = d0 % 10;

    d1 = q + 9*d3 + 5*d2 + d1;
    q = d1 / 10;
    d1 = d1 % 10;
    if (d1) { first_digit = 1; }

    d2 = q + 2*d2;
    q = d2 / 10;
    d2 = d2 % 10;
    if (d2) { first_digit = 2; }

    d3 = q + 4*d3;
    q = d3 / 10;
    d3 = d3 % 10;
    if (d3) { first_digit = 3; }

    d4 = q;
    if (d4) { first_digit = 4; }

    if (width) {
        // width is 1-based; change to 0-based
        if (width > 4) {
            width = 4;
        } else {
            --width;
        }
        if (flags.zeropad) {
            addSign(buf, n, flags);
            for (unsigned i = width; i > first_digit; --i) {
                *buf = '0';
                ++buf;
            }
        } else {
            for (unsigned i = width; i > first_digit; --i) {
                *buf = ' ';
                ++buf;
            }
            addSign(buf, n, flags);
        }
    } else {
        addSign(buf, n, flags);
    }

    switch (first_digit) {
        case 4: *buf = DTOCHAR(d4); ++buf;
        case 3: *buf = DTOCHAR(d3); ++buf;
        case 2: *buf = DTOCHAR(d2); ++buf;
        case 1: *buf = DTOCHAR(d1); ++buf;
    }
    *buf = DTOCHAR(d0); ++buf;
    *buf = '\0';
    return buf;
}

static char *zu16toa(char *buf, uint16_t n, unsigned width, fmt_flags_t flags)
{
    uint8_t d4, d3, d2, d1, q; // yes, 8 bits are enough for these
    uint16_t d0;
    unsigned first_digit = 0;

    d0 = n & 0xF;
    d1 = (n >> 4) & 0xF;
    d2 = (n >> 8) & 0xF;
    d3 = (n >> 12) & 0xF;

    d0 = 6*(d3 + d2 + d1) + d0;
    q = d0 / 10;
    d0 = d0 % 10;

    d1 = q + 9*d3 + 5*d2 + d1;
    q = d1 / 10;
    d1 = d1 % 10;
    if (d1) { first_digit = 1; }

    d2 = q + 2*d2;
    q = d2 / 10;
    d2 = d2 % 10;
    if (d2) { first_digit = 2; }

    d3 = q + 4*d3;
    q = d3 / 10;
    d3 = d3 % 10;
    if (d3) { first_digit = 3; }

    d4 = q;
    if (d4) { first_digit = 4; }

    if (width) {
        // width is 1-based; change to 0-based
        if (width > 4) {
            width = 4;
        } else {
            --width;
        }
        if (flags.zeropad) {
            for (unsigned i = width; i > first_digit; --i) {
                *buf = '0';
                ++buf;
            }
        } else {
            for (unsigned i = width; i > first_digit; --i) {
                *buf = ' ';
                ++buf;
            }
        }
    }

    switch (first_digit) {
        case 4: *buf = DTOCHAR(d4); ++buf;
        case 3: *buf = DTOCHAR(d3); ++buf;
        case 2: *buf = DTOCHAR(d2); ++buf;
        case 1: *buf = DTOCHAR(d1); ++buf;
    }
    *buf = DTOCHAR(d0); ++buf;
    *buf = '\0';
    return buf;
}

char *zi32toa(char *buf, int32_t n, unsigned width, fmt_flags_t flags)
{
    uint8_t n0, n1, n2, n3, n4, n5, n6, n7;
    uint8_t a8, a7, a6, a5, q; // yes, 8 bits are enough for these
    uint16_t a4, a3, a2, a1, a0;
    uint8_t d0, d1, d2, d3, d4, d5, d6, d7, d8, d9;
    unsigned first_digit = 0;

    uint32_t absn = n < 0 ? -n : n;
    n0 = absn & 0xF;
    n1 = (absn >> 4) & 0xF;
    n2 = (absn >> 8) & 0xF;
    n3 = (absn >> 12) & 0xF;
    n4 = (absn >> 16) & 0xF;
    n5 = (absn >> 20) & 0xF;
    n6 = (absn >> 24) & 0xF;
    n7 = (absn >> 28) & 0xF;

    a0 = 6 * (n7 + n6 + n5 + n4 + n3 + n2 + n1) + n0;
    if (a0) {
        q = a0 / 10;
        d0 = a0 % 10;
    } else {
        q = d0 = 0;
    }

    a1 = q + 5*n7 + n6 + 7*n5 + 3*n4 + 9*n3 + 5*n2 + n1;
    if (a1) {
        q = a1 / 10;
        d1 = a1 % 10;
        if (d1) { first_digit = 1; }
    } else {
        q = d1 = 0;
    }

    a2 = q + 4*n7 + 2*n6 + 5*n5 + 5*n4 + 2*n2;
    if (a2) {
        q = a2 / 10;
        d2 = a2 % 10;
        if (d2) { first_digit = 2; }
    } else {
        q = d2 = 0;
    }

    a3 = q + 5*n7 + 7*n6 + 8*n5 + 5*n4 + 4*n3;
    if (a3) {
        q = a3 / 10;
        d3 = a3 % 10;
        if (d3) { first_digit = 3; }
    } else {
        q = d3 = 0;
    }

    a4 = q + 3*n7 + 7*n6 + 4*n5 + 6*n4;
    if (a4) {
        q = a4 / 10;
        d4 = a4 % 10;
        if (d4) { first_digit = 4; }
    } else {
        q = d4 = 0;
    }

    a5 = q + 4*n7 + 7*n6;
    if (a5) {
        q = a5 / 10;
        d5 = a5 % 10;
        if (d5) { first_digit = 5; }
    } else {
        q = d5 = 0;
    }

    a6 = q + 8*n7 + 6*n6 + n5;
    if (a6) {
        q = a6 / 10;
        d6 = a6 % 10;
        if (d6) { first_digit = 6; }
    } else {
        q = d6 = 0;
    }

    a7 = q + 6*n7 + n6;
    if (a7) {
        q = a7 / 10;
        d7 = a7 % 10;
        if (d7) { first_digit = 7; }
    } else {
        q = d7 = 0;
    }

    a8 = q + 2*n7;
    if (a8) {
        q = a8 / 10;
        d8 = a8 % 10;
        if (d8) { first_digit = 8; }
    } else {
        q = d8 = 0;
    }

    d9 = q;
    if (d9) { first_digit = 9; }

    if (width) {
        // width is 1-based; change to 0-based
        if (width > 9) {
            width = 9;
        } else {
            --width;
        }
        if (flags.zeropad) {
            addSign(buf, n, flags);
            for (unsigned i = width; i > first_digit; --i) {
                *buf = '0';
                ++buf;
            }
        } else {
            for (unsigned i = width; i > first_digit; --i) {
                *buf = ' ';
                ++buf;
            }
            addSign(buf, n, flags);
        }
    } else {
        addSign(buf, n, flags);
    }

    switch (first_digit) {
        case 9: *buf = DTOCHAR(d9); ++buf;
        case 8: *buf = DTOCHAR(d8); ++buf;
        case 7: *buf = DTOCHAR(d7); ++buf;
        case 6: *buf = DTOCHAR(d6); ++buf;
        case 5: *buf = DTOCHAR(d5); ++buf;
        case 4: *buf = DTOCHAR(d4); ++buf;
        case 3: *buf = DTOCHAR(d3); ++buf;
        case 2: *buf = DTOCHAR(d2); ++buf;
        case 1: *buf = DTOCHAR(d1); ++buf;
    }
    *buf = DTOCHAR(d0); ++buf;
    *buf = '\0';
    return buf;
}

static char *zu32toa(char *buf, uint32_t n, unsigned width, fmt_flags_t flags)
{
    uint8_t n0, n1, n2, n3, n4, n5, n6, n7;
    uint8_t a8, a7, a6, a5, q; // yes, 8 bits are enough for these
    uint16_t a4, a3, a2, a1, a0;
    uint8_t d0, d1, d2, d3, d4, d5, d6, d7, d8, d9;
    unsigned first_digit = 0;

    n0 = n & 0xF;
    n1 = (n >> 4) & 0xF;
    n2 = (n >> 8) & 0xF;
    n3 = (n >> 12) & 0xF;
    n4 = (n >> 16) & 0xF;
    n5 = (n >> 20) & 0xF;
    n6 = (n >> 24) & 0xF;
    n7 = (n >> 28) & 0xF;

    a0 = 6 * (n7 + n6 + n5 + n4 + n3 + n2 + n1) + n0;
    if (a0) {
        q = a0 / 10;
        d0 = a0 % 10;
    } else {
        q = d0 = 0;
    }

    a1 = q + 5*n7 + n6 + 7*n5 + 3*n4 + 9*n3 + 5*n2 + n1;
    if (a1) {
        q = a1 / 10;
        d1 = a1 % 10;
        if (d1) { first_digit = 1; }
    } else {
        q = d1 = 0;
    }

    a2 = q + 4*n7 + 2*n6 + 5*n5 + 5*n4 + 2*n2;
    if (a2) {
        q = a2 / 10;
        d2 = a2 % 10;
        if (d2) { first_digit = 2; }
    } else {
        q = d2 = 0;
    }

    a3 = q + 5*n7 + 7*n6 + 8*n5 + 5*n4 + 4*n3;
    if (a3) {
        q = a3 / 10;
        d3 = a3 % 10;
        if (d3) { first_digit = 3; }
    } else {
        q = d3 = 0;
    }

    a4 = q + 3*n7 + 7*n6 + 4*n5 + 6*n4;
    if (a4) {
        q = a4 / 10;
        d4 = a4 % 10;
        if (d4) { first_digit = 4; }
    } else {
        q = d4 = 0;
    }

    a5 = q + 4*n7 + 7*n6;
    if (a5) {
        q = a5 / 10;
        d5 = a5 % 10;
        if (d5) { first_digit = 5; }
    } else {
        q = d5 = 0;
    }

    a6 = q + 8*n7 + 6*n6 + n5;
    if (a6) {
        q = a6 / 10;
        d6 = a6 % 10;
        if (d6) { first_digit = 6; }
    } else {
        q = d6 = 0;
    }

    a7 = q + 6*n7 + n6;
    if (a7) {
        q = a7 / 10;
        d7 = a7 % 10;
        if (d7) { first_digit = 7; }
    } else {
        q = d7 = 0;
    }

    a8 = q + 2*n7;
    if (a8) {
        q = a8 / 10;
        d8 = a8 % 10;
        if (d8) { first_digit = 8; }
    } else {
        q = d8 = 0;
    }

    d9 = q;
    if (d9) { first_digit = 9; }

    if (width) {
        // width is 1-based; change to 0-based
        if (width > 9) {
            width = 9;
        } else {
            --width;
        }
        if (flags.zeropad) {
            for (unsigned i = width; i > first_digit; --i) {
                *buf = '0';
                ++buf;
            }
        } else {
            for (unsigned i = width; i > first_digit; --i) {
                *buf = ' ';
                ++buf;
            }
        }
    }

    switch (first_digit) {
        case 9: *buf = DTOCHAR(d9); ++buf;
        case 8: *buf = DTOCHAR(d8); ++buf;
        case 7: *buf = DTOCHAR(d7); ++buf;
        case 6: *buf = DTOCHAR(d6); ++buf;
        case 5: *buf = DTOCHAR(d5); ++buf;
        case 4: *buf = DTOCHAR(d4); ++buf;
        case 3: *buf = DTOCHAR(d3); ++buf;
        case 2: *buf = DTOCHAR(d2); ++buf;
        case 1: *buf = DTOCHAR(d1); ++buf;
    }
    *buf = DTOCHAR(d0); ++buf;
    *buf = '\0';
    return buf;
}

#if UINT_MAX == UINT16_MAX
#define zxtoa zx16toa
#define zitoa zi16toa
#define zutoa zu16toa
#elif UINT_MAX == UINT32_MAX
#define zxtoa zx32toa
#define zitoa zi32toa
#define zutoa zu32toa
#elif UINT_MAX == UINT64_MAX
#define zxtoa zx64toa
#define zitoa zx64toa /* TODO: int64 decimal printing */
#define zutoa zx64toa /* TODO: uint64 decimal printing */
#else
#error UINT_MAX unsupported
#endif
#if ULONG_MAX == UINT32_MAX
#define zlxtoa zx32toa
#define zltoa zi32toa
#define zultoa zu32toa
#elif ULONG_MAX == UINT64_MAX
#define zlxtoa zx64toa
#define zltoa zx64toa /* TODO: int64 decimal printing */
#define zultoa zx64toa /* TODO: uint64 decimal printing */
#else
#error ULONG_MAX unsupported
#endif
#define zllxtoa zx64toa
#define zlltoa zx64toa /* TODO: int64 decimal printing */
#define zulltoa zx64toa /* TODO: uint64 decimal printing */

// WARNING: saturates to INT32_MIN/INT32_MAX; fraction limited to 4 digits
static char *zftoaf(char *buf, float f, unsigned width, unsigned precision, fmt_flags_t flags)
{
    if (!isfinite(f)) {
        if (isnanf(f)) {
            memcpy(buf, "NAN", sizeof("NAN"));
            buf += strlen(buf);
            return buf;
        } else if (isinff(f) == -1) {
            memcpy(buf, "-INF", sizeof("-INF"));
            buf += strlen(buf);
            return buf;
        } else {
            memcpy(buf, "INF", sizeof("INF"));
            buf += strlen(buf);
            return buf;
        }
    }
    if (flags.exp == exp_none && fabsf(f) > (INT32_MAX - 1)) {
        flags.exp = exp_e;
    }
    int exponent = 0;
    if (flags.exp) {
        if (fabsf(f) > 0.0) {
            exponent = log10f(fabsf(f));
            f *= powf(10, -exponent);
            if (!(int32_t)f) {
                f *= 10.0;
                --exponent;
            }
        } else {
            exponent = 0;
        }
    }
    float frnd;
    float fmul;
    float rounded;
    switch(precision) {
        case 0: frnd = 0.5e-0; fmul = 1e0; break;
        case 1: frnd = 0.5e-1; fmul = 1e1; break;
        case 2: frnd = 0.5e-2; fmul = 1e2; break;
        case 3: frnd = 0.5e-3; fmul = 1e3; break;
        case 4: frnd = 0.5e-4; fmul = 1e4; break;
        case 5: frnd = 0.5e-5; fmul = 1e5; break;
        case 6: frnd = 0.5e-6; fmul = 1e6; break;
        case 7: frnd = 0.5e-7; fmul = 1e7; break;
        case 8: frnd = 0.5e-8; fmul = 1e8; break;
        default:
            precision = 9;
            frnd = 0.5e-9;
            fmul = 1.e9;
            break;
    }
    if (f < 0.0) {
        rounded = f - frnd;
    } else {
        rounded = f + frnd;
    }
    int32_t whole = rounded;
    if (flags.exp) {
        if (whole >= 10) {
            rounded *= 0.1;
            ++exponent;
            whole = rounded;
        }
    }
    if (!whole && signbit(f)) {
        *buf = '-';
        ++buf;
        flags.sign = auto_sign;
    }
    if (whole > INT16_MAX || width > 4) {
        buf = zltoa(buf, whole, width, flags);
    } else {
        buf = zitoa(buf, whole, width, flags);
    }
    if (precision || flags.exp) {
        *buf = '.'; ++buf;
    }
    if (precision) {
        float fraction = fabsf(fmul * (rounded - whole));
        const fmt_flags_t fraction_flags = { .zeropad = 1 };
        if (fraction > UINT16_MAX || precision > 4) {
            buf = zultoa(buf, fraction, precision, fraction_flags);
        } else {
            buf = zutoa(buf, fraction, precision, fraction_flags);
        }
    }
    if (flags.exp == exp_e) {
        buf[0] = 'e'; ++buf;
        const fmt_flags_t exponent_flags = { .sign = always_sign, .zeropad = 1 };
        zitoa(buf, exponent, 2, exponent_flags);
    } else if (flags.exp == exp_E) {
        buf[0] = 'E'; ++buf;
        const fmt_flags_t exponent_flags = { .sign = always_sign, .zeropad = 1 };
        zitoa(buf, exponent, 2, exponent_flags);
    }
    return buf;
}

// WARNING: saturates to INT32_MIN/INT32_MAX; fraction limited to 9 digits
static char *zftoal(char *buf, long double f, unsigned width, unsigned precision, fmt_flags_t flags)
{
    if (!isfinite(f)) {
        if (isnanl(f)) {
            memcpy(buf, "NAN", sizeof("NAN"));
            buf += strlen(buf);
            return buf;
        }
        if (isinfl(f) == -1) {
            memcpy(buf, "-INF", sizeof("-INF"));
            buf += strlen(buf);
            return buf;
        } else {
            memcpy(buf, "INF", sizeof("INF"));
            buf += strlen(buf);
            return buf;
        }
    }
    if (flags.exp == exp_none && fabsl(f) > (INT32_MAX - 1)) {
        flags.exp = exp_e;
    }
    int exponent = 0;
    if (flags.exp) {
        if (fabsl(f) > 0.0) {
            exponent = log10l(fabsf(f));
            f *= powl(10, -exponent);
            if (!(int32_t)f) {
                f *= 10.0;
                --exponent;
            }
        } else {
            exponent = 0;
        }
    }
    long double frnd;
    long double fmul;
    long double rounded;
    switch(precision) {
        case 0: frnd = 0.5e-0; fmul = 1e0; break;
        case 1: frnd = 0.5e-1; fmul = 1e1; break;
        case 2: frnd = 0.5e-2; fmul = 1e2; break;
        case 3: frnd = 0.5e-3; fmul = 1e3; break;
        case 4: frnd = 0.5e-4; fmul = 1e4; break;
        case 5: frnd = 0.5e-5; fmul = 1e5; break;
        case 6: frnd = 0.5e-6; fmul = 1e6; break;
        case 7: frnd = 0.5e-7; fmul = 1e7; break;
        case 8: frnd = 0.5e-8; fmul = 1e8; break;
        default:
            precision = 9;
            frnd = 0.5e-9;
            fmul = 1.e9;
            break;
    }
    if (f < 0.0) {
        rounded = f - frnd;
    } else {
        rounded = f + frnd;
    }
    int32_t whole = rounded;
    if (flags.exp) {
        if (whole >= 10) {
            rounded *= 0.1;
            ++exponent;
            whole = rounded;
        }
    }
    if (!whole && signbit(f)) {
        *buf = '-';
        ++buf;
        flags.sign = auto_sign;
    }
    if (whole > INT16_MAX || width > 4) {
        buf = zltoa(buf, whole, width, flags);
    } else {
        buf = zitoa(buf, whole, width, flags);
    }
    if (precision || flags.exp) {
        *buf = '.'; ++buf;
    }
    if (precision) {
        long double fraction = fabsl(fmul * (rounded - whole));
        const fmt_flags_t fraction_flags = { .zeropad = 1 };
        if (fraction > UINT16_MAX || precision > 4) {
            buf = zultoa(buf, fraction, precision, fraction_flags);
        } else {
            buf = zutoa(buf, fraction, precision, fraction_flags);
        }
    }
    if (flags.exp == exp_e) {
        buf[0] = 'e'; ++buf;
        const fmt_flags_t exponent_flags = { .sign = always_sign, .zeropad = 1 };
        zitoa(buf, exponent, 3, exponent_flags);
    } else if (flags.exp == exp_E) {
        buf[0] = 'E'; ++buf;
        const fmt_flags_t exponent_flags = { .sign = always_sign, .zeropad = 1 };
        zitoa(buf, exponent, 3, exponent_flags);
    }
    return buf;
}

// endptr must be non-null
static inline fmt_flags_t getFlags(char *subspec, char **endptr)
{
    fmt_flags_t flags = { 0 };
    char *flag;
    char *end_of_flags = strpbrk(subspec, ".123456789");
    char flag_dlm = 0;
    if (end_of_flags) {
        // cap the flags string
        flag_dlm = *end_of_flags;
        *end_of_flags = '\0';
    }
    while ((flag = strpbrk(subspec, "0-+ #"))) {
        if (*flag == '-') {
            flags.leftAlign = 1; // '-' flag not currently supported
        } else if (*flag == '+') {
            flags.sign = always_sign;
        } else if (*flag == ' ' && flags.sign != always_sign) {
            flags.sign = sign_or_space;
        } else if (*flag == '#') { // '#' flag not currently supported
            flags.altForm = 1;
        } else if (*flag == '0') {
            flags.zeropad = 1;
        }
        ++subspec;
    }
    if (end_of_flags) {
        // restore sub-spec
        *end_of_flags = flag_dlm;
    }
    *endptr = subspec;
    return flags;
}

// endptr must be non-null
static inline int getWidth(char *subspec, char **endptr)
{
    if (*subspec == '*') {
        // special case; grab width from args
        *endptr = subspec + 1;
        return ARG_SPECIFIED;
    }
    *endptr = subspec;
    return strtol(subspec, endptr, 10);
}

// endptr must be non-null
static inline int getPrecision(char *subspec, char **endptr)
{
    char *delimiter = strchr(subspec, '.');
    if (delimiter == NULL) {
        *endptr = subspec;
        return PRECISION_UNSPECIFIED;
    }
    char *precstr = delimiter + 1;
    if (*precstr == '*') {
        // special case; grab width from args
        *endptr = subspec + 1;
        return ARG_SPECIFIED;
    }
    *endptr = precstr;
    int precval = strtol(precstr, endptr, 10);
    if (*endptr == precstr) {
        // couldn't parse precision
        return PRECISION_UNSPECIFIED;
    } else {
        return precval;
    }
}

typedef enum length_e {
    length_char,
    length_int,
    length_long,
    length_long_long,
    length_size_t,
} length_t;

static inline length_t getLength(const char * subspec) {
    if (strstr(subspec, "ll")) {
        return length_long_long;
    }
    if (strchr(subspec, 'l')) {
        return length_long;
    }
    if (strchr(subspec, 'L')) {
        return length_long_long;
    }
    if (strstr(subspec, "hh")) {
        return length_char;
    }
    return length_int;
}

static inline void getSubspec(char *buf, unsigned maxlen, const char *escape, const char *specifier)
{
    size_t len = specifier - (escape + 1);
    len = len >= maxlen ? maxlen - 1 : len;
    ZCOAP_MEMCPY(buf, escape + 1, len);
    buf[len] = '\0';
}

#define GMINF 0.0001 // min for %f output style when %g specified
#define GMAXF 999999.9 // max for %f output style when %g specified

size_t zvsnprintf(char *buf, size_t n, const char *fmt, va_list ap)
{
    size_t remain = n, len = 0;
    const char *src = fmt;
    char *dest = buf;
    const char *escape;
    while ((escape = strchr(src, '%'))) {
        size_t toklen = escape - src;
        len += toklen;
        if (toklen >= remain) {
            toklen = remain;
        }
        remain -= toklen;
        ZCOAP_MEMCPY(dest, src, toklen);
        dest += toklen;
        const char *tok = NULL;
        const char *spec = strpbrk(escape + 1, "duxXfFeEgGs%iocpaA");
        if (spec) {
            src = spec + 1;
            char tmp[sizeof(MAX_DEC_FMT_I32"."MAX_DEC_FMT_I32)];
            char subspec[sizeof(MAX_WIDTH_SUB_SPEC)];
            getSubspec(subspec, sizeof(subspec), escape, spec);
            char *endptr = subspec;
            fmt_flags_t flags = getFlags(endptr, &endptr);
            unsigned width = getWidth(endptr, &endptr);
            if (width == ARG_SPECIFIED) { width = va_arg(ap, int); }
            unsigned precision = getPrecision(endptr, &endptr);
            if (precision == ARG_SPECIFIED) { precision = va_arg(ap, int); }
            length_t length = getLength(endptr);
            if (*spec == '%') {
                tok = "%";
            } else if (   *spec == 'd' || *spec == 'i'
                       || *spec == 'u'
                       || *spec == 'x' || *spec == 'X'
                       || *spec == 'o') {
                if (   length == length_char
                    || length == length_int
                    || length == length_size_t) {
                    unsigned val = 0;
                    if (length == length_char) {
                        val = va_arg(ap, int);
                    } else if (length == length_int) {
                        val = va_arg(ap, int);
                    } else if (length == length_size_t) {
                        val = va_arg(ap, size_t);
                    }
                    if (*spec == 'd' || *spec == 'i') {
                        zitoa(tmp, val, width, flags);
                    } else if (*spec == 'u') {
                        zutoa(tmp, val, width, flags);
                    } else if (*spec == 'x' || *spec == 'X' || *spec == 'o') {
                        // cmon; octal? no, we'll print that as hex
                        zxtoa(tmp, val, width, flags);
                    }
                } else if (length == length_long) {
                    long unsigned val = va_arg(ap, long int);
                    if (*spec == 'd' || *spec == 'i') {
                        zltoa(tmp, val, width, flags);
                    } else if (*spec == 'u') {
                        zultoa(tmp, val, width, flags);
                    } else if (*spec == 'x' || *spec == 'X' || *spec == 'o') {
                        // cmon; octal? no, we'll print that as hex
                        zlxtoa(tmp, val, width, flags);
                    }
                } else if (length == length_long_long) {
                    long long unsigned val = va_arg(ap, long long int);
                    if (*spec == 'd' || *spec == 'i') {
                        zltoa(tmp, val, width, flags); // TODO: 64-bit signed decimal conversion?
                    } else if (*spec == 'u') {
                        zultoa(tmp, val, width, flags); // TODO: 64-bit unsigned decimal conversion?
                    } else if (*spec == 'x' || *spec == 'X' || *spec == 'o') {
                        // cmon; octal? no, we'll print that as hex
                        zllxtoa(tmp, val, width, flags);
                    }
                }
                tok = tmp;
            } else if (   *spec == 'f' || *spec == 'F'
                       || *spec == 'e' || *spec == 'E'
                       || *spec == 'g' || *spec == 'G'
                       || *spec == 'a' || *spec == 'A') {
                if (length == length_long_long) {
                    long double val = va_arg(ap, long double);
                    if (*spec == 'e' || *spec == 'a') {
                        flags.exp = exp_e;
                    } else if (*spec == 'E' || *spec == 'A') {
                        flags.exp = exp_E;
                    } else  if (*spec == 'g' || *spec == 'G') {
                        long double absv = fabsl(val);
                        if (absv < GMINF || absv > GMAXF) {
                            if (*spec == 'g') {
                                flags.exp = exp_e;
                            } else {
                                flags.exp = exp_E;
                            }
                        }
                    }
                    zftoal(tmp, val, width, precision == PRECISION_UNSPECIFIED ? DEFAULT_PRECISION : precision, flags);
                } else {
                    double val = va_arg(ap, double);
                    if (*spec == 'e' || *spec == 'a') {
                        flags.exp = exp_e;
                    } else if (*spec == 'E' || *spec == 'A') {
                        flags.exp = exp_E;
                    } else  if (*spec == 'g' || *spec == 'G') {
                        double absv = fabs(val);
                        if (absv < GMINF || absv > GMAXF) {
                            if (*spec == 'g') {
                                flags.exp = exp_e;
                            } else {
                                flags.exp = exp_E;
                            }
                        }
                    }
                    zftoa(tmp, val, width, precision == PRECISION_UNSPECIFIED ? DEFAULT_PRECISION : precision, flags);
                }
                tok = tmp;
            } else if (*spec == 'p') {
                void *val = va_arg(ap, void *);
                zxtoa(tmp, (unsigned long) /* TODO: whoa, this aint portable... hmmm  */val, width, flags); // presuming here that native arithmetic width is wide enough for a data pointer
                tok = tmp;
            } else if (*spec == 's') {
                tok = va_arg(ap, const char *);
            } else if (*spec == 'c') {
                tmp[0] = va_arg(ap, int);
                tmp[1] = '\0';
                tok = tmp;
            }
        } else if (strchr(escape + 1, 'n')) {
            src = spec + 1;
            *va_arg(ap, int *) = n - remain;
        } else {
            src = escape + 1;
        }
        if (tok) {
            toklen = strlen(tok);
            len += toklen;
            if (toklen > remain) {
                toklen = remain;
            }
            remain -= toklen;
            ZCOAP_MEMCPY(dest, tok, toklen);
            dest += toklen;
        }
    }
    {
        size_t toklen = strlen(src);
        len += toklen;
        if (toklen >= remain) {
            toklen = remain;
        }
        remain -= toklen;
        ZCOAP_MEMCPY(dest, src, toklen);
        dest += toklen;
        if (remain) {
            *dest = '\0';
        } else if (n) {
            buf[n - 1] = '\0';
        }
    }
    return len;
}

size_t zsnprintf(char *buf, size_t n, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    size_t len = zvsnprintf(buf, n, fmt, ap);
    va_end(ap);
    return len;
}

#endif /* USE_ZCOAP_SNPRINTF */
