#include <stdarg.h>
#include <unistd.h>  // write, STDOUT_FILENO

#include "print.h"

#define stdout egalito_stdout
#define stderr egalito_stderr

#ifdef __cplusplus
extern "C" {
#endif

static void _strcpy(char *dest, const char *src) {
    do {
        *dest++ = *src;
    } while(*src++);
}

static void write_char(int stream, char c) {
    (void)write(stream, &c, 1);
}

static void write_string(int stream, const char *message) {
    if(!message) message = "(null)";

    size_t length = 0;
    while(message[length]) length ++;
    
    (void)write(stream, message, length);
}

static void write_hex(int stream, unsigned long number) {
    char buffer[2+8+8];
    int i = 2+8+8;
    
    unsigned long shift = 0;
    for(;;) {
        unsigned long digit = (number >> shift) & 0xf;
        if(digit <= 9) buffer[--i] = digit + '0';
        else buffer[--i] = (digit-10) + 'a';
        
        shift += 4;
        if(shift == 32 && (number >> shift) == 0) break;
        if(shift == 64) break;
    }
    /*buffer[--i] = 'x';
    buffer[--i] = '0';*/
    (void)write(stream, buffer + i, 2+8+8-i);
}

static void write_decimal(int stream, unsigned long number) {
    char buffer[20];
    int i = 20;
    do {
        buffer[--i] = (number % 10) + '0';
        number /= 10;
    } while(number);
    (void)write(stream, buffer + i, 20-i);
}

static void decimal_to_string(unsigned long number, char *s) {
    char buffer[20+1] = {0};
    int i = 20;
    do {
        buffer[--i] = (number % 10) + '0';
        number /= 10;
    } while(number);
    _strcpy(s, buffer + i);
}

static void hex_to_string(unsigned long number, char *s) {
    char buffer[2+8+8+1] = {0};
    int i = 2+8+8;
    
    unsigned long shift = 0;
    for(;;) {
        unsigned long digit = (number >> shift) & 0xf;
        if(digit <= 9) buffer[--i] = digit + '0';
        else buffer[--i] = (digit-10) + 'a';
        
        shift += 4;
        if(shift == 32 && (number >> shift) == 0) break;
        if(shift == 64) break;
    }
    _strcpy(s, buffer + i);
}

int NAME(printf) (const char *format, ...) {
    va_list args;
    va_start(args, format);

    int r = NAME(vfprintf) (stdout, format, args);

    va_end(args);
    return r;
}

int NAME(fprintf) (int stream, const char *format, ...) {
    va_list args;
    va_start(args, format);

    int r = NAME(vfprintf) (stream, format, args);

    va_end(args);
    return r;
}

int NAME(vfprintf) (int stream, const char *format, va_list args) {
    for(const char *begin = format; *begin; ) {
        if(*begin == '%') {
            begin ++;
            while((*begin >= '0' && *begin <= '9') || *begin == '-') begin++;
            switch(*begin) {
            case 'c':
                write_char(stream, va_arg(args, int));
                break;
            case 's':
                write_string(stream, va_arg(args, const char *));
                break;
            case 'd':
                write_decimal(stream, va_arg(args, int));
                break;
            case 'u':
                write_decimal(stream, va_arg(args, unsigned));
                break;
            case 'x':
                write_hex(stream, va_arg(args, unsigned));
                break;
            case 'p':
                write_hex(stream, (unsigned long)va_arg(args, void *));
                break;
            case 'l':
                switch(*++begin) {
                case 'd':
                    write_decimal(stream, va_arg(args, long));
                    break;
                case 'u':
                    write_decimal(stream, va_arg(args, unsigned long));
                    break;
                case 'x':
                    write_hex(stream, va_arg(args, unsigned long));
                    break;
                }
                break;
            }
            begin ++;
        }
        else {
            const char *p = begin;
            while(*p && *p != '%') p ++;
            (void)write(stream, begin, p - begin);
            
            begin = p;
        }
    }
    
    return 0;
}

int NAME(sprintf) (char *s, const char *format, ...) {
    va_list args;
    va_start(args, format);

    int r = NAME(vsnprintf) (s, (size_t)-1, format, args);

    va_end(args);
    return r;
}

int NAME(snprintf) (char *s, size_t size, const char *format, ...) {
    va_list args;
    va_start(args, format);

    int r = NAME(vsnprintf) (s, size, format, args);

    va_end(args);
    return r;
}

int NAME(vsnprintf) (char *s, size_t size, const char *format, va_list args) {
    for(const char *begin = format; *begin; ) {
        if(*begin == '%') {
            begin++;
            while((*begin >= '0' && *begin <= '9') || *begin == '-') begin++;
            switch(*begin) {
            case 'c':
                *s++ = (char) va_arg(args, int);
                break;
            case 's':
                _strcpy(s, va_arg(args, const char *));
                while(*s) s++;
                break;
            case 'd':
                decimal_to_string(va_arg(args, int), s);
                while(*s) s++;
                break;
            case 'u':
                decimal_to_string(va_arg(args, unsigned), s);
                while(*s) s++;
                break;
            case 'x':
                hex_to_string(va_arg(args, unsigned), s);
                while(*s) s++;
                break;
            case 'p':
                hex_to_string((unsigned long)va_arg(args, void *), s);
                while(*s) s++;
                break;
            case 'l':
                switch(*++begin) {
                case 'd':
                    decimal_to_string(va_arg(args, int), s);
                    while(*s) s++;
                    break;
                case 'u':
                    decimal_to_string(va_arg(args, unsigned long), s);
                    while(*s) s++;
                    break;
                case 'x':
                    hex_to_string(va_arg(args, unsigned long), s);
                    while(*s) s++;
                    break;
                }
                break;
            }
            begin ++;
        }
        else {
            const char *p = begin;
            while(*p && *p != '%') *s++ = *p++;
            
            begin = p;
        }
    }
    
    return 0;
}

int NAME(puts) (const char *s) {
    write_string(stdout, s);
    write_char(stdout, '\n');
    return 0;  // non-negative on success
}

#ifdef __cplusplus
}  // extern "C"
#endif
