#ifndef EGALITO_RUNTIME_MANAGE_GS_H
#define EGALITO_RUNTIME_MANAGE_GS_H

#include "chunk/gstable.h"

class ManageGS {
public:
    static void init(GSTable *gsTable);

    static void setEntry(GSTable *gsTable, GSTableEntry::IndexType index,
        address_t value);
};

#endif
