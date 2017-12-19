#include "external.h"
#include "concrete.h"
#include "serializer.h"
#include "visitor.h"
#include "operation/find2.h"
#include "log/log.h"

void ExternalSymbol::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    writer.writeString(name);
    writer.write<uint32_t>(type);
    writer.write<uint32_t>(bind);
    writer.writeID(op.assign(resolved));
    writer.writeID(op.assign(resolvedModule));
}

bool ExternalSymbol::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    name = reader.readString();
    type = static_cast<Symbol::SymbolType>(reader.read<uint32_t>());
    bind = static_cast<Symbol::BindingType>(reader.read<uint32_t>());
    resolved = op.lookup(reader.readID());
    resolvedModule = op.lookupAs<Module>(reader.readID());
    return reader.stillGood();
}

void ExternalSymbol::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

void ExternalSymbolList::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    op.serializeChildren(this, writer);
}

bool ExternalSymbolList::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    op.deserializeChildren(this, reader);
    return reader.stillGood();
}

void ExternalSymbolList::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

ExternalSymbol *ExternalSymbolFactory::makeExternalSymbol(Symbol *symbol) {
    return makeExternalSymbol(symbol->getName(),
        symbol->getType(), symbol->getBind(), symbol->getVersion(), nullptr);
}

ExternalSymbol *ExternalSymbolFactory::makeExternalSymbol(
    const std::string &name, Symbol::SymbolType type, Symbol::BindingType bind,
    const SymbolVersion *version, Chunk *resolved) {

    auto symbolList = makeExternalSymbolList();
    // !!! linear search
    for(auto xs : CIter::children(symbolList)) {
        if(xs->getName() == name && xs->getType() == type
            && xs->getBind() == bind) {

            return xs;
        }
    }

    auto xSymbol = new ExternalSymbol(name, type, bind, version);
    xSymbol->setResolved(resolved);
    symbolList->getChildren()->add(xSymbol);
    return xSymbol;
}

ExternalSymbolList *ExternalSymbolFactory::makeExternalSymbolList() {
    if(!module->getExternalSymbolList()) {
        module->setExternalSymbolList(new ExternalSymbolList());
    }
    return module->getExternalSymbolList();
}

#if 0
void ExternalSymbolFactory::resolveAllSymbols(Program *program) {
    for(auto lib : CIter::children(program->getLibraryList())) {
        if(lib->getModule() == nullptr) {
            LOG(1, "WARNING: resolving external symbols but Module \""
                << lib->getName() << "\" is not loaded");
        }
    }

    for(auto xSymbol : CIter::children(module->getExternalSymbolList())) {
        resolveOneSymbol(program, xSymbol);
    }
}

void ExternalSymbolFactory::resolveOneSymbol(Program *program,
    ExternalSymbol *xSymbol) {

    if(xSymbol->getType() == Symbol::TYPE_FUNC
        || xSymbol->getType() == Symbol::TYPE_IFUNC) {

        auto resolved = ChunkFind2(program)
            .findFunction(xSymbol->getName().c_str());
        xSymbol->setResolved(resolved);
        if(resolved && resolved->getParent()) {
            xSymbol->setResolvedModule(dynamic_cast<Module *>(
                resolved->getParent()->getParent()));
        }
    }
    else {
        LOG(1, "WARNING: don't know how to resolve external symbol \""
            << xSymbol->getName() << "\" of type " << xSymbol->getType());
    }
}
#endif
