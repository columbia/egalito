#!/usr/bin/env python
import python_egalito as eg
import cmd2 as cmd
import readline
import sys
import time
import os
import colorama

#readline.set_completer_delims(' \t\n')


class EgalitoShell(cmd.Cmd):


    prompt = colorama.Style.BRIGHT + 'etshell> ' + colorama.Style.RESET_ALL

    def __init__(self, conductor_setup):
        self.__conductor_setup = conductor_setup
        self.__histfile = os.path.expanduser('.etshell_history')
        self.__histfile_size = 1000
        super().__init__()

    def preloop(self):
        if os.path.exists(self.__histfile):
            readline.read_history_file(self.__histfile)

    def postloop(self):
        readline.set_history_length(self.__histfile_size)
        readline.write_history_file(self.__histfile)

    def do_parse(self, line):
        """
        Parses the given ELF file.
        """
        self.__conductor_setup.parse_elf_files(line, False, False)

    def do_parse2(self, line):
        """
        Parses the given ELF and all its shared libraries.
        """
        self.__conductor_setup.parse_elf_files(line, True, False)

    def do_parse3(self, line):
        """
        Parses the given ELF and all its shared libraries. Injects egalito.
        """
        self.__conductor_setup.parse_elf_files(line, True, True)

    def do_disass(self, line):
        """
        Disassembles the given function name/address.
        """
        address = None
        if ('0x' in line):
            address = int(line, 16)
            line = hex(address)

        conductor = self.__conductor_setup.get_conductor()
        chunk_find = eg.ChunkFind2(conductor)
        func = None

        if address:
            func = chunk_find.find_function_containing(address)
        else:
            func = chunk_find.find_function(line, None)

        chunk_dumper = eg.ChunkDumper()

        if (func):
            func.accept(chunk_dumper)
        else:
            print("%s not found" % (line))

    def do_reassign(self, line):
        """
        Allocates a sandbox and assigns functions new addresses
        """
        self.__conductor_setup.make_loader_sandbox()
        self.__conductor_setup.move_code_assign_addresses()

    def do_q(self, line):
        """
        Quit etshell.
        """
        return True

    def do_EOF(self, line):
        return True

    def cmdloop_with_keyboard_interrupt(self):
        do_quit = False
        while do_quit != True:
            try:
                self.cmdloop()
                do_quit = True
            except KeyboardInterrupt:
                sys.stdout.write('\n')

if __name__ == '__main__':

    conductor_setup = eg.ConductorSetup()
    EgalitoShell(conductor_setup).cmdloop_with_keyboard_interrupt()
