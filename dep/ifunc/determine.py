import gdb

class DetermineIFuncTarget (gdb.Command):
    "determine the IFunc target."

    def __init__ (self):
        super (DetermineIFuncTarget, self).__init__("DetermineIFuncTarget",
                gdb.COMMAND_DATA,
                gdb.COMPLETE_NONE)

    def invoke (self, arg, from_tty):
        #ifuncs = ["memset", "memcpy", "mempcpy", "memmove", "memcmp", "memchr", "strcmp", "strncmp", "strcasecmp", "strncasecmp", "strlen", "strnlen", "strcpy", "stpcpy", "strchr", "strrchr", "strchrnul", "strspn", "strcspn", "strcat", "strcasecmp_l", "rawmemchr", "wmemset", "wcslen", "wcsnlen", "cos"]
        # ifuncs = ["cos", "memchr", "memcmp", "memcpy", "memmove", "mempcpy", "memset", "newlocale", "rawmemchr", "stpcpy", "strcasecmp", "strcasecmp_l", "strcat", "strchr", "strchrnul", "strcmp", "strcpy", "strcspn", "strlen", "strncasecmp", "strncmp", "strncpy", "strnlen", "strrchr", "strspn", "wcslen", "wcsnlen", "wmemset"]
        ifuncs = [ "atan", "atanf", "ceil", "ceilf", "cos", "cosf", "exp", "expf", "floor", "floorf", "log", "logf", "memchr", "memcmp", "memcpy","__memcpy_chk", "memmove", "mempcpy", "memrchr", "memset", "newlocale", "rawmemchr", "rint", "rintf", "sin", "sincos", "sincosf", "sinf", "stpcpy", "stpncpy", "strcasecmp", "strcasecmp_l", "strcat", "strchr", "strchrnul", "strcmp", "strcpy", "strcspn", "strlen", "strncasecmp", "strncmp", "strncpy", "strnlen", "strpbrk", "strrchr", "strspn", "strstr", "tan", "tanf", "trunc", "truncf", "wcslen", "wcsnlen", "wmemchr", "wmemcmp", "wmemset" ]
        with open('ifunc.h', 'w') as f:
            for ifunc in ifuncs:
                target = self.determine("'%s@plt'" % ifunc)
                f.write("KNOWN_IFUNC_ENTRY(%s, %s)\n" % (ifunc, target))

    def determine (self, arg):
        #print("arg is %s" % (arg))
        value = gdb.parse_and_eval(arg)
        if value is not None:
            #print("trampoline at %x" % value.address)
            gdb.execute('set $pc = 0x%x' % int(value.address), False, True)
            gdb.execute('si', False, True)
            #print('PC = %x' % gdb.selected_frame().pc())
            name = gdb.selected_frame().name()
            if(name == 'memcpy'): name = '__memcpy_sse2_unaligned'
            if(name == 'top12'): name = '__expf_sse2'
            return name


DetermineIFuncTarget()
