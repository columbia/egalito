import gdb

class DetermineIFuncTarget (gdb.Command):
    "determine the IFunc target."

    def __init__ (self):
        super (DetermineIFuncTarget, self).__init__("DetermineIFuncTarget",
                gdb.COMMAND_DATA,
                gdb.COMPLETE_NONE)

    def invoke (self, arg, from_tty):
        ifuncs = ["memset", "memcpy", "mempcpy", "memmove", "memcmp", "memchr", "strcmp", "strncmp", "strcasecmp", "strlen", "strnlen", "strcpy", "stpcpy", "strchr", "strrchr", "strchrnul", "strspn", "strcspn", "strcat", "strcasecmp_l", "rawmemchr", "wmemset", "wcslen", "wcsnlen", "cos"]
        with open('ifunc.h', 'w') as f:
            for ifunc in ifuncs:
                target = self.determine("'%s@plt'" % ifunc)
                f.write("KNOWN_IFUNC_ENTRY(%s, %s)\n" % (ifunc, target))

    def determine (self, arg):
        #print("arg is %s" % (arg))
        value = gdb.parse_and_eval(arg)
        if value is not None:
            #print("trampoline at %x" % value.address)
            gdb.execute('set $pc = 0x%x' % value.address, False, True)
            gdb.execute('si', False, True)
            #print('PC = %x' % gdb.selected_frame().pc())
            return gdb.selected_frame().name()


DetermineIFuncTarget()
