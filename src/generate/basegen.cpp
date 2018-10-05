#include "basegen.h"

ElfGeneratorImpl::ElfGeneratorImpl(Program *program, SandboxBacking *backing)
    : data(new ElfDataImpl(program, backing)) {

}
