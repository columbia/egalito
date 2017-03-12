import gdb

class ReconstructCommand(gdb.Command):
    "Reconstruct struct definitions from debugging info"

    def __init__(self, subcommand = ""):
        command = "reconstruct"
        if(subcommand != ""):
            command = command + " " + subcommand
        super().__init__(command,
            gdb.COMMAND_DATA,
            gdb.COMPLETE_NONE, True)
        self.init_run()

    def invoke(self, arg, from_tty):
        self.init_run()
        structType = gdb.lookup_type(arg)
        self.initial_print(arg)
        for field in structType.fields():
            bitpos = field.bitpos
            if(bitpos % 8 != 0):
                raise "can't handle bitfields yet"
            position = int(bitpos / 8)
            name = field.name
            self.process_field(field, position, name)
        self.final_print(arg)

    def init_run(self):
        pass
    def initial_print(self, arg):
        pass
    def final_print(self, arg):
        pass

    def process_field(self, field, position, name):
        print("+%4d %4d %-40s %s" % (position, field.type.sizeof, name, field.type))

class ReconstructCCommand(ReconstructCommand):
    "Pretty-print information as a C structure"

    def __init__(self, subcommand = "c"):
        super().__init__(subcommand)

    def output(self, name, position, size, fieldType, substitutions):
        code = fieldType.strip_typedefs().code

        declType = ["char", "[" + str(size) + "]", None]
        if(substitutions):
            if(code == gdb.TYPE_CODE_PTR):
                declType = ["void *", "", "%p"]
            elif(code == gdb.TYPE_CODE_INT):
                if(size == 1): declType = ["unsigned char", "", "char(%d)"]
                elif(size == 2): declType = ["unsigned short", "", "0x%x"]
                elif(size == 4): declType = ["unsigned int", "", "0x%x"]
                elif(size == 8): declType = ["unsigned long", "", "0x%lx"]
            elif(code == gdb.TYPE_CODE_BOOL):
                declType = ["unsigned char", "", "bool(%d)"]

        self.output_statement(declType, name, position, size, fieldType)

    def output_statement(self, declType, name, position, size, fieldType):
        #print(code)
        print("    %-15s %-30s %-8s; // +%-4d  %s" \
            % (declType[0], name, declType[1], position, fieldType))

    def init_run(self):
        self.calculatedPos = 0
        self.paddingNumber = 1

    def process_field(self, field, position, name):
        fieldType = field.type
        size = field.type.sizeof

        # add padding struct members if necessary
        if(self.calculatedPos < position):
            self.output("__pad" + str(self.paddingNumber),
                self.calculatedPos, position - self.calculatedPos,
                gdb.lookup_type("char"), False)
            self.paddingNumber += 1
            self.calculatedPos = position
        elif(self.calculatedPos > position):
            raise "error: calculated position exceeds reported position"
        self.calculatedPos += size

        # output this member of the struct
        self.output(name, position, size, fieldType, True)

    def initial_print(self, arg):
        print("%s {" % arg)
    def final_print(self, arg):
        print("}; // expected size: %d" % self.calculatedPos)

class ReconstructDumpCommand(ReconstructCCommand):
    "Generate code to dump data structure with printf"

    def __init__(self):
        super().__init__("dump")

    def output_statement(self, declType, name, position, size, fieldType):
        if(declType[2] == None):
            declType[2] = '%p'  # just print arrays as a pointer for now
        string = '%-15s %-30s %-8s = ' + declType[2].replace('%', '%%') + '  // %s'
        string = '    printf("' + string + '\\n", s->%s);'
        print(string % (declType[0], name, declType[1], fieldType, name))

    def initial_print(self, arg):
        pass
    def final_print(self, arg):
        pass

class ReconstructAssignCommand(ReconstructCCommand):
    "Generate code to assign all structure members to reference values"

    def __init__(self):
        super().__init__("assign")

    def output(self, name, position, size, fieldType, substitutions):
        if(name.startswith("__pad")): return
        super().output(name, position, size, fieldType, substitutions)

    def output_statement(self, declType, name, position, size, fieldType):
        if(declType[2] == None):
            print('    printf("    char _data' + str(self.dataCount) + '[] = {\\n        ");')
            print('    for(int i = 0; i < ' + str(size) + '; i ++) {')
            print('        if((i + 1) % 10 == 0) printf("\\n        ");')
            print('        printf("0x%02x, ", s->' + name + '[i] & 0xff);')
            print('    }')
            print('    printf("};\\n");')
            print('    printf("    memcpy(s->' + name + ', _data' + str(self.dataCount) + ', ' + str(size) + ');\\n");')
            self.dataCount += 1
            return

        string = '    s->%-30s = ' + declType[2].replace('%', '%%') + ';  // %s'
        string = '    printf("' + string + '\\n", s->%s);'
        print(string % (name, fieldType, name))

    def init_run(self):
        self.dataCount = 1
        super().init_run()

    def initial_print(self, arg):
        pass
    def final_print(self, arg):
        pass

ReconstructCommand()
ReconstructCCommand()
ReconstructDumpCommand()
ReconstructAssignCommand()
