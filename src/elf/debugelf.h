#ifndef EGALITO_INTROSPECT_GENELF_H
#define EGALITO_INTROSPECT_GENELF_H

#include <stddef.h>
#include <elf.h>

class Function;

/** Ported from Shuffler. Originally written by Kent.

    This code is designed to only use system calls directly with no
    external dependencies.
*/
class DebugElf {
private:
    Elf64_Sym *symbols;
    size_t symbols_size, symbols_used;
    char *strtable;
    size_t strtable_size, strtable_used;
    unsigned long start, end;
public:
    DebugElf();
    ~DebugElf();

    void writeTo(int fd);
    void writeTo(const char *filename);

    void add(unsigned long address, unsigned long size, const char *name);
    void add(Function *func, const char *suffix);
};

#endif
