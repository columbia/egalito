#include "program.h"
#include "visitor.h"

Program::Program(ElfSpaceList *spaceList)
    : main(nullptr), egalito(nullptr), spaceList(spaceList) {

}

void Program::add(Module *module) {
    getChildren()->add(module);
}

void Program::setMain(Module *module) {
    this->main = module;
}

void Program::setEgalito(Module *module) {
    this->egalito = module;
}

void Program::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
