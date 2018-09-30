#include <cstring>  // for memcpy
#include "writer.h"
#include "chunk/link.h"
#include "concrete.h"

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

// DataLinkedControlFlow Instruction
void InstrWriterCString::visit(DataLinkedControlFlowInstruction *controlFlow) {
    controlFlow->writeTo(target, true);
}
void InstrWriterCppString::visit(DataLinkedControlFlowInstruction *controlFlow) {
    controlFlow->writeTo(target, true);
}
void InstrWriterGetData::visit(DataLinkedControlFlowInstruction *controlFlow) {
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

// StackFrameInstruction
void InstrWriterCString::visit(StackFrameInstruction *stackFrame) {
#ifdef ARCH_X86_64
    stackFrame->writeTo(target);
#endif
}
void InstrWriterCppString::visit(StackFrameInstruction *stackFrame) {
#ifdef ARCH_X86_64
    stackFrame->writeTo(target);
#endif
}
void InstrWriterGetData::visit(StackFrameInstruction *stackFrame) {
#ifdef ARCH_X86_64
    stackFrame->writeTo(data);
#endif
}

// LiteralInstruction
void InstrWriterCString::visit(LiteralInstruction *literal) {
    std::memcpy(target, literal->getData().c_str(), literal->getSize());
}
void InstrWriterCppString::visit(LiteralInstruction *literal) {
    target.append(literal->getData());
}
void InstrWriterGetData::visit(LiteralInstruction *literal) {
    data = literal->getData();
}

// LinkedLiteralInstruction
void InstrWriterCString::visit(LinkedLiteralInstruction *linked) {
#ifdef ARCH_AARCH64
    linked->writeTo(target);
#endif
}
void InstrWriterCppString::visit(LinkedLiteralInstruction *linked) {
#ifdef ARCH_AARCH64
    linked->writeTo(target);
#endif
}
void InstrWriterGetData::visit(LinkedLiteralInstruction *linked) {
#ifdef ARCH_AARCH64
    linked->writeTo(data);
#endif
}
