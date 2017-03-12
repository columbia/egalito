import gdb

class ReconstructCommand (gdb.Command):
    "Reconstruct struct definitions from debugging info"

    def __init__(self):
        super(ReconstructCommand, self).__init__("reconstruct",
            gdb.COMMAND_DATA,
            gdb.COMPLETE_NONE, True)

    def invoke(self, arg, from_tty):
        structType = gdb.lookup_type(arg)
        for field in structType.fields():
            bitpos = field.bitpos
            if(bitpos % 8 != 0):
                raise "can't handle bitfields yet"
            position = int(bitpos / 8)
            name = field.name
            print("+%4d %4d %-40s %s" % (position, field.type.sizeof, name, field.type))

class ReconstructCCommand (gdb.Command):
    "Pretty-print information as a C structure"

    def __init__(self):
        super(ReconstructCCommand, self).__init__("reconstruct c",
            gdb.COMMAND_SUPPORT,
            gdb.COMPLETE_NONE, True)

    def output(self, name, position, size, fieldType, substitutions):
        code = fieldType.strip_typedefs().code

        declType = ["char", "[" + str(size) + "]"]
        if(substitutions):
            if(code == gdb.TYPE_CODE_PTR):
                declType = ["void *", ""]
            elif(code == gdb.TYPE_CODE_INT):
                if(size == 1): declType = ["unsigned char", ""]
                elif(size == 2): declType = ["unsigned short", ""]
                elif(size == 4): declType = ["unsigned int", ""]
                elif(size == 8): declType = ["unsigned long", ""]
            elif(code == gdb.TYPE_CODE_BOOL):
                declType = ["unsigned char", ""]

        #print(code)
        print("    %-15s %-30s %-8s; // +%-4d  %s" \
            % (declType[0], name, declType[1], position, fieldType))

    def invoke(self, arg, from_tty):
        structType = gdb.lookup_type(arg)
        calculatedPos = 0
        paddingNumber = 1
        print("%s {" % arg)
        for field in structType.fields():
            bitpos = field.bitpos
            if(bitpos % 8 != 0):
                raise "can't handle bitfields yet"
            position = int(bitpos / 8)
            name = field.name
            fieldType = field.type
            size = field.type.sizeof

            # add padding struct members if necessary
            if(calculatedPos < position):
                self.output("__pad" + str(paddingNumber),
                    calculatedPos, position - calculatedPos,
                    gdb.lookup_type("char"), False)
                paddingNumber += 1
                calculatedPos = position
            elif(calculatedPos > position):
                raise "error: calculated position exceeds reported position"
            calculatedPos += size

            # output this member of the struct
            self.output(name, position, size, fieldType, True)
        print("}; // expected size: %d" % calculatedPos)

class ReconstructDumpCommand (gdb.Command):
    "Generate code to dump data structure with printf"

    def __init__(self):
        super(ReconstructDumpCommand, self).__init__("reconstruct dump",
            gdb.COMMAND_SUPPORT,
            gdb.COMPLETE_NONE, True)

    def output(self, name, position, size, fieldType, substitutions):
        code = fieldType.strip_typedefs().code

        declType = ["char", "[" + str(size) + "]", "%p"]
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

        string = '%-15s %-30s %-8s = ' + declType[2].replace('%', '%%') + '  // %s'
        string = '    printf("' + string + '\\n", s->%s);'
        print(string % (declType[0], name, declType[1], fieldType, name))

    def invoke(self, arg, from_tty):
        structType = gdb.lookup_type(arg)
        calculatedPos = 0
        paddingNumber = 1
        for field in structType.fields():
            bitpos = field.bitpos
            if(bitpos % 8 != 0):
                raise "can't handle bitfields yet"
            position = int(bitpos / 8)
            name = field.name
            fieldType = field.type
            size = field.type.sizeof

            # add padding struct members if necessary
            if(calculatedPos < position):
                self.output("__pad" + str(paddingNumber),
                    calculatedPos, position - calculatedPos,
                    gdb.lookup_type("char"), False)
                paddingNumber += 1
                calculatedPos = position
            elif(calculatedPos > position):
                raise "error: calculated position exceeds reported position"
            calculatedPos += size

            # output this member of the struct
            self.output(name, position, size, fieldType, True)

class ReconstructAssignCommand (gdb.Command):
    "Generate code to assign all structure members to reference values"

    def __init__(self):
        super(ReconstructAssignCommand, self).__init__("reconstruct assign",
            gdb.COMMAND_SUPPORT,
            gdb.COMPLETE_NONE, True)

    def output(self, name, position, size, fieldType, substitutions):
        if(name.startswith("__pad")): return
        code = fieldType.strip_typedefs().code

        declType = ["char", "[" + str(size) + "]", None]
        if(substitutions):
            if(code == gdb.TYPE_CODE_PTR):
                declType = ["void *", "", "0x%lx"]
            elif(code == gdb.TYPE_CODE_INT):
                if(size == 1): declType = ["unsigned char", "", "char(%d)"]
                elif(size == 2): declType = ["unsigned short", "", "0x%x"]
                elif(size == 4): declType = ["unsigned int", "", "0x%x"]
                elif(size == 8): declType = ["unsigned long", "", "0x%lx"]
            elif(code == gdb.TYPE_CODE_BOOL):
                declType = ["unsigned char", "", "bool(%d)"]

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

    def invoke(self, arg, from_tty):
        structType = gdb.lookup_type(arg)
        calculatedPos = 0
        paddingNumber = 1
        self.dataCount = 1
        for field in structType.fields():
            bitpos = field.bitpos
            if(bitpos % 8 != 0):
                raise "can't handle bitfields yet"
            position = int(bitpos / 8)
            name = field.name
            fieldType = field.type
            size = field.type.sizeof

            # add padding struct members if necessary
            if(calculatedPos < position):
                self.output("__pad" + str(paddingNumber),
                    calculatedPos, position - calculatedPos,
                    gdb.lookup_type("char"), False)
                paddingNumber += 1
                calculatedPos = position
            elif(calculatedPos > position):
                raise "error: calculated position exceeds reported position"
            calculatedPos += size

            # output this member of the struct
            self.output(name, position, size, fieldType, True)

ReconstructCommand()
ReconstructCCommand()
ReconstructDumpCommand()
ReconstructAssignCommand()
