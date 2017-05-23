#include <cstring>  // for memcpy
#include "writer.h"
#include "chunk/link.h"
#include "concrete.h"

// RawInstruction
void InstrWriterCString::visit(RawInstruction *raw) {
    auto storage = raw->getStorage();
    std::memcpy(target, storage.getData().c_str(), storage.getSize());
}
void InstrWriterCppString::visit(RawInstruction *raw) {
    target.append(raw->getStorage().getData());
}
void InstrWriterGetData::visit(RawInstruction *raw) {
    data = raw->getStorage().getData();
}

// IsolatedInstruction
void InstrWriterCString::visit(IsolatedInstruction *isolated) {
    auto assembly = isolated->getAssembly();
    std::memcpy(target, assembly->getBytes(), assembly->getSize());
}
void InstrWriterCppString::visit(IsolatedInstruction *isolated) {
    auto assembly = isolated->getAssembly();
    target.append(assembly->getBytes(), assembly->getSize());
}
void InstrWriterGetData::visit(IsolatedInstruction *isolated) {
    auto assembly = isolated->getAssembly();
    data.assign(assembly->getBytes(), assembly->getSize());
}

// LinkedInstruction
void InstrWriterCString::visit(LinkedInstruction *linked) {
    linked->writeTo(target, useDisplacements());
}
void InstrWriterCppString::visit(LinkedInstruction *linked) {
    linked->writeTo(target, useDisplacements());
}
void InstrWriterGetData::visit(LinkedInstruction *linked) {
    linked->writeTo(data, useDisplacements());
}

// ControlFlow Instruction
void InstrWriterCString::visit(ControlFlowInstruction *controlFlow) {
    // always use a displacement for direct jumps, unless it's to a PLT entry
    bool useDisp = useDisplacements();
    if(!dynamic_cast<PLTLink *>(controlFlow->getLink())
        && !dynamic_cast<SymbolOnlyLink *>(controlFlow->getLink())) {

        useDisp = true;
    }
    controlFlow->writeTo(target, useDisp);
}
void InstrWriterCppString::visit(ControlFlowInstruction *controlFlow) {
    bool useDisp = useDisplacements();
    if(!dynamic_cast<PLTLink *>(controlFlow->getLink())
        && !dynamic_cast<SymbolOnlyLink *>(controlFlow->getLink())) {

        useDisp = true;
    }
    controlFlow->writeTo(target, useDisp);
}
void InstrWriterGetData::visit(ControlFlowInstruction *controlFlow) {
    bool useDisp = useDisplacements();
    if(!dynamic_cast<PLTLink *>(controlFlow->getLink())
        && !dynamic_cast<SymbolOnlyLink *>(controlFlow->getLink())) {

        useDisp = true;
    }
    controlFlow->writeTo(data, useDisp);
}

void InstrWriterMakeReloc::visit(LinkedInstruction *linked) {
    if(!linked->getLink()) return;

    madeReloc = true;
}

void InstrWriterMakeReloc::visit(ControlFlowInstruction *controlFlow) {
    if(!controlFlow->getLink()) return;

    madeReloc = true;
}

// LiteralInstruction
void InstrWriterCString::visit(LiteralInstruction *literal) {
    visit(static_cast<RawInstruction *>(literal));
}
void InstrWriterCppString::visit(LiteralInstruction *literal) {
    visit(static_cast<RawInstruction *>(literal));
}
void InstrWriterGetData::visit(LiteralInstruction *literal) {
    visit(static_cast<RawInstruction *>(literal));
}

