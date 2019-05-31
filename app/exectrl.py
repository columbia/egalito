import gdb

# pcount [diff]
# pcount save
# pcount abs
# count is_number
# condstart
# autocheckpoint 10
# checkpoint (make new checkpoint)
# condrestart 1
# condgo is_number -10
# condgo is_number 1000
# condgo is_number +10
# condgo -10
class CondStartCommand(gdb.Command):
    "Go back to an earlier invocation of a function."

    def __init__(self):
        super(CondStartCommand, self).__init__("condstart",
            gdb.COMMAND_RUNNING,
            gdb.COMPLETE_NONE, True)

    def invoke(self, arg, from_tty):
        gdb.execute("start", to_string=False)
        gdb.execute("checkpoint", to_string=False)

class CondGoCommand(gdb.Command):
    "Go back to an earlier invocation of a function."

    def __init__(self):
        super(CondGoCommand, self).__init__("condgo",
            gdb.COMMAND_RUNNING,
            gdb.COMPLETE_NONE, True)

    def invoke(self, arg, from_tty):
        argv = arg.split()
        function = ''
        delta = 0
        if(len(argv) == 2):
            function = argv[0]
            delta = int(argv[1])
        elif(len(argv) == 1):
            function = gdb.selected_frame().name()
            delta = int(argv[0])
        else:
            print("Usage: condgo [func] N")
            return

        count = int(gdb.parse_and_eval("'__counter_" + function + "'"))
        target_count = count + delta
        if(target_count <= 0):
            print("Warning:", function,
                "hasn't been called that many times, going to first call")
            target_count = 1

        cmd = "restart 1"
        gdb.execute(cmd, to_string=True)
        restart_count = int(gdb.parse_and_eval("'__counter_" + function + "'"))

        final_count = restart_count - target_count
        if(final_count >= 0):
            print("Error: checkpoint is not old enough to go to", function, target_count)
            return

        print(function, count, "=>", target_count)
        cmd = "set var '__counter_{}'={}".format(function, final_count)
        gdb.execute(cmd, to_string=True)

        b = gdb.Breakpoint("egalito_cond_watchpoint_hit")
        #b.commands = "set var '__counter_{}'={}".format(function, target_count)
        #print(b)
        gdb.execute("continue", to_string=True)

class PrintCountersCommand(gdb.Command):
    "Print egalito function counters."

    def __init__(self):
        super(PrintCountersCommand, self).__init__("pcount",
            gdb.COMMAND_RUNNING,
            gdb.COMPLETE_NONE, True)

        self.old_value = {}

    def invoke(self, arg, from_tty):
        data = gdb.execute("info variables __counter_", to_string=True)
        self.counters = []
        for line in data.split('\n'):
            try:
                (addr,name) = line.split()
                if(int(addr, 16) != 0):
                    self.counters.append(name)
            except Exception:
                pass
        
        value = {}
        for c in self.counters:
            value[c] = int(gdb.parse_and_eval("'" + c + "'"))

        diff_value = {}
        for c in self.counters:
            if c in self.old_value:
                # print(c,"was",self.old_value[c],"and is now",value[c])
                diff_value[c] = value[c] - self.old_value[c]
            else:
                diff_value[c] = value[c]
            self.old_value[c] = value[c]

        #self.print_alphabetical()
        #print()
        self.print_magnitude(diff_value)

    def print_alphabetical(self):
        for name in sorted(self.counters):
            if(self.value[name] != 0):
                print("{}\t{}".format(self.value[name], name))

    def print_magnitude(self, values):
        l = []
        for name in self.counters:
            if(values[name] != 0):
                l.append((values[name], name))
        for (value,name) in sorted(l, reverse=True):
            print("{}\t{}".format(value, name))

CondStartCommand()
CondGoCommand()
PrintCountersCommand()
