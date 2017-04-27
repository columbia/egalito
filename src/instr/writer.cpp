#include <cstring>  // for memcpy
#include "writer.h"
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
    controlFlow->writeTo(target, true);  // always use disp for jumps
}
void InstrWriterCppString::visit(ControlFlowInstruction *controlFlow) {
    controlFlow->writeTo(target, true);
}
void InstrWriterGetData::visit(ControlFlowInstruction *controlFlow) {
    controlFlow->writeTo(data, true);
}

void InstrWriterMakeReloc::visit(LinkedInstruction *linked) {
    if(!linked->getLink()) return;

    madeReloc = true;
}

void InstrWriterMakeReloc::visit(ControlFlowInstruction *controlFlow) {
    if(!controlFlow->getLink()) return;

    madeReloc = true;
}
