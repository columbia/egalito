#ifndef EGALITO_PASS_PROFILE_SAVE_H
#define EGALITO_PASS_PROFILE_SAVE_H

#include "chunkpass.h"
#include "chunk/dataregion.h"

class ProfileSavePass : public ChunkPass {
public:
    virtual void visit(Module *module);
private:
    std::pair<DataSection *, DataSection*> getDataSections(Module *module);
    Link *appendString(DataSection *nameSection, const std::string &name);
};

#endif
