#include <fstream>
#include <sstream>

#include "parseoverride.h"

#include "log/log.h"

BlockBoundaryOverride *BlockBoundaryOverride::parse(std::istream &stream,
    std::string &line) {

    BlockBoundaryOverride *result = new BlockBoundaryOverride();

    while(std::getline(stream, line)) {
        if(line[0] != ' ') return result;
        std::istringstream ss(line);
        address_t start;
        size_t size;
        ss >> std::hex >> start >> size;
        result->overrideList.emplace_back(std::make_pair(start, size));
    }

    return result;
}

ParseOverride ParseOverride::instance;

void ParseOverride::parse(const std::string &from) {
    parseFile(from);
}

void ParseOverride::parseFile(const std::string &filename) {
    std::ifstream f(filename);

    if(!f) {
        LOG(1, "Failed to parse overrides from \"" << filename << "\"");
        return;
    }

    // XXX: currently all numbers need to be hex
    // blockoverride "A" func
    //     0x0 0x50
    //     0x100 0x110

    std::string line;
    while(true) {
        if(line == "") {
            if(!std::getline(f, line)) break;
            continue;
        }

        std::istringstream ss(line);
        std::string type;
        ss >> type;

        OverrideContext context;
        std::string str;
        address_t addr;

        std::string contextType;
        while(ss >> contextType) {
            if(contextType == "module")
                ss >> str, std::get<0>(context) = "module-" + str;
            else if(contextType == "func")
                ss >> str, std::get<1>(context) = str;
            else if(contextType == "address")
                ss >> addr, std::get<2>(context) = addr;
            else {
                LOG(1, "Failed to parse override context: "
                    "unknown context type \"" << contextType << "\"");
            }
        }

        if(type == "blockoverride") {
            OverrideContainerInsert<
                BlockBoundaryOverride, OverrideContext>::insert(
                blockOverrides, context, BlockBoundaryOverride::parse(f, line));
        }
        else {
            LOG(1, "Failed to parse override: unknown type \""
                << type << "\"");
        }
    }
}

BlockBoundaryOverride *ParseOverride::getBlockBoundaryOverride(
    const OverrideContext &where) {

    return OverrideContainerLookup<
        BlockBoundaryOverride, OverrideContext>::lookup(blockOverrides, where);
}
