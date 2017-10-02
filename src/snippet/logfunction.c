#include <stdio.h>

#define TARGET_IS_MAGENTA   1

#define LOG_MAX    128

static struct {
    int dir;
    unsigned long address;
} logbuf[LOG_MAX] __attribute__((section(".data")));
static int log_i = 0;
static void egalito_log_function_info(unsigned long address, int dir);

extern int _printf(const char *fmt, ...) __attribute((weak));


void egalito_log_function_entry(unsigned long address) {
    egalito_log_function_info(address - 12, 1);
}

void egalito_log_function_exit(unsigned long address) {
    egalito_log_function_info(address + 4, -1);
}

void egalito_log_function_info(unsigned long address, int dir) {
    if(log_i < LOG_MAX) {
        logbuf[log_i].address = address;
        logbuf[log_i].dir = dir;
        log_i++;
    }
}

size_t egalito_long_to_buf(char *buf, unsigned long num) {
    char *p = buf;
    if(num == 0) {
        *buf = '0';
        return 1;
    }
    while(num > 0) {
        int rem = num & 0xFu;
        *p++ = (rem > 9) ? (rem - 10) + 'a' : rem + '0';
        num >>= 4;
    }
    size_t ret = p - buf;
    --p;
    while(buf < p) {
        char tmp = *p;
        *p = *buf;
        *buf = tmp;
        p--, buf++;
    }
    return ret;
}

void egalito_dump_logs() {
#if !TARGET_IS_MAGENTA
    char buf[32];
#endif

    for(int i = 0; i < log_i; i++) {
#if !TARGET_IS_MAGENTA
        size_t pos = egalito_long_to_buf(buf, i);
        buf[pos++] = ' ';
        buf[pos++] = (logbuf[i].dir > 0) ? '>' : '<';
        buf[pos++] = ' ';
        pos += egalito_long_to_buf(&buf[pos], logbuf[i].address);
        buf[pos++] = 0;
        puts(buf);  // must be used in the original target program
#else
        _printf("%d %c %lx\n",
            i, (logbuf[i].dir > 0) ? '>' : '<', logbuf[i].address);
#endif
    }
}

