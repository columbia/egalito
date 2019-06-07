import gdb
import random

class CounterState:
    # state: dictionary of names => counter values
    def __init__(self, state={}):
        self.state = state.copy()

    def add(self, other_state):
        for c in other_state.state:
            self.state[c] += other_state.state[c]

    def subtract(self, other_state):
        for c in other_state.state:
            self.state[c] -= other_state.state[c]

    def get(self, key):
        if key in self.state:
            return self.state[key]
        return 0

recent_checkpoint = "1"
virtual_state = CounterState()
last_printed_state = CounterState()

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
        count += virtual_state.get("__counter_" + function)
        target_count = count + delta
        if(target_count <= 0):
            print("Warning:", function,
                "hasn't been called that many times, going to first call")
            target_count = 1

        global recent_checkpoint
        cmd = "restart " + recent_checkpoint
        gdb.execute(cmd, to_string=True)

        gdb.execute("checkpoint", to_string=True)

        checkpoints = gdb.execute("info checkpoints", to_string=True)
        print(checkpoints)
        last_c = checkpoints.split('\n')[-2]
        print(last_c)
        c = last_c[2:].split()[0]
        print(c)
        recent_checkpoint = c

        restart_count = int(gdb.parse_and_eval("'__counter_" + function + "'"))
        restart_count += virtual_state.get("__counter_" + function)

        value = {}
        global last_printed_state
        for c in last_printed_state.state:
            value[c] = int(gdb.parse_and_eval("'" + c + "'"))
            value[c] += virtual_state.get(c)
        last_printed_state = CounterState(value)

        final_count = restart_count - target_count
        if(final_count >= 0):
            print("Error: checkpoint is not old enough to go to", function, target_count)
            return

        print(function, count, "=>", target_count)
        cmd = "set var '__counter_{}'={}".format(function, final_count)
        gdb.execute(cmd, to_string=True)
        virtual_state.state["__counter_" + function] = target_count

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

        #diff_value = {}
        #for c in self.counters:
        #    if c in self.old_value:
        #        # print(c,"was",self.old_value[c],"and is now",value[c])
        #        diff_value[c] = value[c] - self.old_value[c]
        #    else:
        #        diff_value[c] = value[c]
        #    self.old_value[c] = value[c]
        diff_value = CounterState(value)
        global last_printed_state
        diff_value.subtract(last_printed_state)
        diff_value.add(virtual_state)
        last_printed_state = CounterState(value)

        #self.print_alphabetical()
        #print()
        self.print_magnitude(diff_value.state)

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

# -----


'''
set var *(unsigned long *)(((char *)&egalito_gs_base) + 0x170) = *(unsigned long *)&parse_arguments$rhs$table1

p (unsigned long *)((char *)&egalito_table0_base + 0x10)
$65 = (unsigned long *) 0x30000010 <deregister_tm_clones$table0>

'''

class PrintGSTableCommand(gdb.Command):
    "Print %gs table."

    def __init__(self):
        super(PrintGSTableCommand, self).__init__("pgs",
            gdb.COMMAND_RUNNING,
            gdb.COMPLETE_NONE, True)

    def invoke(self, arg, from_tty):
        try:
            i = 0
            while True:
                cmd = "p/x *(unsigned long *)(((char *)&egalito_gs_base) + {})".format(i)
                data = gdb.execute(cmd, to_string=True)
                value = data.split()[2]
                if(int(value, 16) == 0): break

                cmd = "p (unsigned long *)((char *)&egalito_table0_base + {})".format(i)
                data = gdb.execute(cmd, to_string=True)
                name = data.split()[-1].strip("<>")
                name = name.split("$table0")[0]

                cmd = "p/x *(unsigned long *)((char *)&egalito_table0_base + {})".format(i)
                data = gdb.execute(cmd, to_string=True)
                table0_value = data.split()[2]

                which = 0 if value == table0_value else 1

                print(hex(i), value, which, name)

                i += 8
        except Exception:
            pass

class PrintRHSCommand(gdb.Command):
    "Print rhs functions."

    def __init__(self):
        super(PrintRHSCommand, self).__init__("prhs",
            gdb.COMMAND_RUNNING,
            gdb.COMPLETE_NONE, True)

    def invoke(self, arg, from_tty):
        data = gdb.execute("info functions $rhs", to_string=True)
        self.counters = []
        for line in data.split('\n'):
            try:
                (addr,name) = line.split()
                print(name)
            except Exception:
                pass

class SetGSTableEntryCommand(gdb.Command):
    "Set %gs table."

    def __init__(self):
        super(SetGSTableEntryCommand, self).__init__("setgs",
            gdb.COMMAND_RUNNING,
            gdb.COMPLETE_NONE, True)

    def invoke(self, arg, from_tty):
        argv = arg.split()
        which = 1
        if len(argv) > 1 and argv[1] != "1":
            which = 0
        try:
            cmd = "p/x (unsigned long *)(((char *)&{}$table0) - ((char *)&egalito_table0_base))".format(argv[0])
            #print(cmd)
            data = gdb.execute(cmd, to_string=True)
            index = int(data.split()[2], 16)

            cmd = "set var *(unsigned long *)(((char *)&egalito_gs_base) + {}) = *(unsigned long *)(((char *)&egalito_table{}_base) + {})".format(index, which, index)
            #print(cmd)
            data = gdb.execute(cmd, to_string=True)

        except Exception as e:
            print(e)

class SetAllGSEntriesCommand(gdb.Command):
    "Set %gs table."

    def __init__(self):
        super(SetAllGSEntriesCommand, self).__init__("setallgs",
            gdb.COMMAND_RUNNING,
            gdb.COMPLETE_NONE, True)

    def invoke(self, arg, from_tty):
        argv = arg.split()
        which = 1
        if len(argv) > 0 and argv[0] == "0":
            which = 0
        elif len(argv) > 0 and argv[0] == "-1":
            which = -1
        data = gdb.execute("info functions $rhs", to_string=True)
        self.counters = []
        for line in data.split('\n'):
            try:
                (addr,name) = line.split()
                name = name.split("$rhs")[0]

                cmd = "p/x (unsigned long *)(((char *)&{}$table0) - ((char *)&egalito_table0_base))".format(name)
                #print(cmd)
                data = gdb.execute(cmd, to_string=True)
                index = int(data.split()[2], 16)

                w = which if which >= 0 else random.randint(0,2)
                cmd = "set var *(unsigned long *)(((char *)&egalito_gs_base) + {}) = *(unsigned long *)(((char *)&egalito_table{}_base) + {})".format(index, w, index)
                #print(cmd)
                data = gdb.execute(cmd, to_string=True)

                print(name, "=>", w)
            except Exception as e :
                print(e)



CondStartCommand()
CondGoCommand()
PrintCountersCommand()
PrintGSTableCommand()
PrintRHSCommand()
SetGSTableEntryCommand()
SetAllGSEntriesCommand()
