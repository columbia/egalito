#!/usr/bin/env python
import python_egalito
import cmd

class EgalitoShell(cmd.Cmd):

    prompt = 'etshell> '

    def do_parse(self, line):
        conductor = python_egalito.ConductorSetup()
        conductor.parseElfFiles(line, False, False)
        return True

if __name__ == '__main__':
    EgalitoShell().cmdloop()
