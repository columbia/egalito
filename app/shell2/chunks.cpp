#include <iostream>
#include <typeinfo>
#include "chunks.h"
#include "chunk/chunk.h"
#include "chunk/dump.h"
#include "operation/find2.h"

void ChunkCommands::construct(EgalitoInterface *egalito) {
    fullList->add(new FunctionCommand("init", ArgumentSpecList({}, {}),
        [egalito] (ShellState &state, ArgumentValueList &args) {

        egalito->initializeParsing();
        state.clearReflog();
        state.setChunk(egalito->getProgram());
        return true;
    }, "clears all loaded ELF files"));
    fullList->add(new FunctionCommand("parse", ArgumentSpecList({
        {"-r", ArgumentSpec({"-r"}, ArgumentSpec::TYPE_FLAG)}
    }, {
        ArgumentSpec(ArgumentSpec::TYPE_FILENAME)
    }, 0), [egalito] (ShellState &state, ArgumentValueList &args) {
        auto isRecursive = args.getBool("-r", false);
        if(args.getIndexedCount() > 0) {
            auto filename = args.getIndexed(0).getString();
            auto module = egalito->parse(filename, isRecursive);

            state.setChunk(module);
            return module != nullptr;
        }
        else if(isRecursive) {
            egalito->parseRecursiveDependencies();
            return true;
        }
        else {
            (*args.getOutStream()) << "nothing to do?\n";
            return false;
        }
    }, "parses input ELF files"));
    fullList->add(new FunctionCommand("ls", ArgumentSpecList({
        {"-l", ArgumentSpec({"-l"}, ArgumentSpec::TYPE_FLAG)}
    }, {}),
        [egalito] (ShellState &state, ArgumentValueList &args) {

        auto out = args.getOutStream();
        auto chunk = state.getChunk();
        if(!chunk) return false;
        if(!chunk->getChildren()) return false;

        bool longMode = args.getBool("-l");

        for(auto child : chunk->getChildren()->genericIterable()) {
            if(longMode) {
                (*out) << child->getName() << " " << typeid(*child).name() << std::endl;
            }
            else {
                (*out) << child->getName() << std::endl;
            }
        }
        return true;
    }, "shows all children of current Chunk"));
    fullList->add(new FunctionCommand("cd", ArgumentSpecList({}, {
        ArgumentSpec(ArgumentSpec::TYPE_CHUNK)
    }),
        [egalito] (ShellState &state, ArgumentValueList &args) {

        auto out = args.getOutStream();
        auto chunk = state.getChunk();
        if(!chunk) return false;

        if(args.getIndexedCount() == 0) {
            state.setChunk(egalito->getProgram());
            return true;
        }
        
        auto where = args.getIndexed(0).getString();
        if(where == "..") {
            if(auto parent = state.getChunk()->getParent()) {
                state.setChunk(parent);
            }
            else {
                (*out) << "error: no parent pointer set\n";
                return false;
            }
        }
        else if(where == "-") {
            if(auto last = state.popReflog()) {
                state.setChunk(last);
            }
            else {
                (*out) << "error: no previous chunk location\n";
                return false;
            }
        }
        else {
            if(auto child = chunk->getChildren()->genericFind(where)) {
                state.setChunk(child);
            }
            else {
                (*out) << "error: no child named \"" << where << "\"\n";
                return false;
            }
        }
        return true;
    }, "change to a child Chunk or parent"));
    fullList->add(new FunctionCommand("function", ArgumentSpecList({}, {
        ArgumentSpec(ArgumentSpec::TYPE_STRING)
    }, 1),
        [egalito] (ShellState &state, ArgumentValueList &args) {

        auto out = args.getOutStream();

        auto name = args.getIndexed(0).getString();
        auto found = ChunkFind2(egalito->getProgram()).findFunction(name.c_str());
        if(!found) {
            (*out) << "error: no such function \"" << name << "\"\n";
            return false;
        }
        state.setChunk(found);
        return true;
    }, "change to a child Chunk or parent"));
    fullList->add(new FunctionCommand("disass", ArgumentSpecList({}, {
        ArgumentSpec(ArgumentSpec::TYPE_STRING)
    }),
        [egalito] (ShellState &state, ArgumentValueList &args) {

        auto out = args.getOutStream();
        Chunk *target = nullptr;
        if(args.getIndexedCount() == 0) {
            if(!state.getChunk()) {
                (*out) << "error: no function is selected\n";
                return false;
            }
            target = state.getChunk();
        }
        else {
            auto name = args.getIndexed(0).getString();
            target = ChunkFind2(egalito->getProgram()).findFunction(name.c_str());
            if(!target) {
                (*out) << "error: no such function \"" << name << "\"\n";
                return false;
            }
        }
        ChunkDumper dump;
        target->accept(&dump);
        return true;
    }, "print a disassembly of a given function (or current Chunk)"));
}
