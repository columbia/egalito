#include "program.h"
#include "visitor.h"

Program::Program(ElfSpaceList *spaceList)
    : main(nullptr), egalito(nullptr), spaceList(spaceList) {

}

void Program::add(Module *module) {
    getChildren()->add(module);
}

void Program::addMain(Module *module) {
    add(module);
    this->main = module;
}

void Program::addEgalito(Module *module) {
    add(module);
    this->egalito = module;
}

void Program::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
