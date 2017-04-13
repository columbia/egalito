#!/usr/bin/env python
import python_egalito
import cmd
import readline
import sys

class EgalitoShell(cmd.Cmd):

    prompt = 'etshell> '
    def __init__(self, conductorSetup):
        self.conductorSetup = conductorSetup
        super().__init__()

    def do_parse(self, line):
        self.conductorSetup.parseElfFiles(line, False, False)

    def do_disass(self, line):
        """TODO: Not complete yet"""
        conductor = self.conductorSetup.getConductor()
        chunkFind = python_egalito.ChunkFind2(conductor)
        func = chunkFind.findFunction(line, None)
        print(func.getName())

    def do_EOF(self, line):
        return True

    def cmdloop_with_keyboard_interrupt(self):
        doQuit = False
        while doQuit != True:
            try:
                self.cmdloop()
                doQuit = True
            except KeyboardInterrupt:
                sys.stdout.write('\n')

if __name__ == '__main__':

    conductorSetup = python_egalito.ConductorSetup()
    EgalitoShell(conductorSetup).cmdloop_with_keyboard_interrupt()
