#include "clearspatial.h"

void ClearSpatialPass::visit(FunctionList *functionList) {
    functionList->getChildren()->clearSpatial();
    recurse(functionList);
}

void ClearSpatialPass::visit(Function *function) {
    function->getChildren()->clearSpatial();
    recurse(function);
}

void ClearSpatialPass::visit(Block *block) {
    block->getChildren()->clearSpatial();
}

void ClearSpatialPass::visit(DataRegion *region) {
    region->getChildren()->clearSpatial();
}
