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

void ClearSpatialPass::visit(DataRegionList *regionList) {
    regionList->getChildren()->clearSpatial();
    recurse(regionList);
}

void ClearSpatialPass::visit(DataRegion *region) {
    region->getChildren()->clearSpatial();
    recurse(region);
}

void ClearSpatialPass::visit(DataSection *section) {
    section->getChildren()->clearSpatial();
}
