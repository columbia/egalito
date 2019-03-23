#include <iostream>
#include <typeinfo>
#include "chunks.h"
#include "chunk/chunk.h"

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
    }, 1), [egalito] (ShellState &state, ArgumentValueList &args) {
        auto isRecursive = args.getBool("-r", false);
        auto filename = args.getIndexed(0).getString();
        auto module = egalito->parse(filename, isRecursive);

        state.setChunk(module);
        return module != nullptr;
    }, "parses input ELF files"));
    fullList->add(new FunctionCommand("ls", ArgumentSpecList({
        {"-l", ArgumentSpec({"-l"}, ArgumentSpec::TYPE_FLAG)}
    }, {}),
        [egalito] (ShellState &state, ArgumentValueList &args) {

        auto out = args.getOutStream();
        auto chunk = state.getChunk();
        if(!chunk) return false;

        bool longMode = args.getBool("-l");

        for(auto child : chunk->getChildren()->genericIterable()) {
            if(longMode) {
                (*out) << child->getName() << " " << typeid(child).name() << std::endl;
            }
            else {
                (*out) << child->getName() << std::endl;
            }
        }
        return true;
    }, "shows all children of current Chunk"));
    fullList->add(new FunctionCommand("cd", ArgumentSpecList({}, {
        ArgumentSpec(ArgumentSpec::TYPE_STRING)
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
}
