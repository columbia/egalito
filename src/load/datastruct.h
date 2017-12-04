#ifndef EGALITO_LOAD_DATA_STRUCT_H
#define EGALITO_LOAD_DATA_STRUCT_H

#include <vector>
#include <utility>
#include "types.h"

class ConductorSetup;
class VTableList;
class VTable;

class DataStructMigrator {
private:
    std::vector<std::pair<address_t, uint64_t>> fixupList;
public:
    void migrate(ConductorSetup *setup);
private:
    void migrateList(VTableList *loaderVTableList, VTableList *sourceList);
    void migrateTable(VTable *loaderVTableList, VTable *egalitoVTable);
    void commit();
};

#endif
