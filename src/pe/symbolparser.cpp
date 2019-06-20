#include <fstream>
#include <sstream>
#include <cstring>
#include "symbolparser.h"
#include "log/log.h"

SymbolList *PESymbolParser::buildSymbolList(const std::string &symbolFile) {
    std::ifstream file(symbolFile.c_str());
    if(!file) return nullptr;

    LOG(0, "Parsing symbols from PE symbol file list [" << symbolFile << "]");

    SymbolList *list = new SymbolList();

    std::string line;
    while(std::getline(file, line)) {
        if(line.length() == 0) continue;
        if(line[line.length() - 1] == '\r') line = line.substr(0, line.length() - 1);

        std::vector<std::string> column;
        std::string::size_type start = 0, i = 0;
        bool insideQuotes = false;
        for(i = 0; i < line.length(); ++ i) {
            std::string token;
            if(!insideQuotes && line[i] == ',') {
                token = line.substr(start, i - start);  // exclude ','
                start = i+1;
            }
            else if(i + 1 == line.length()) {
                token = line.substr(start, i - start);
            }
            else if(line[i] == '"') {
                insideQuotes = !insideQuotes;
                continue;
            }
            else continue;

            if(token.length() >= 2
                && token[0] == '"' && token[token.length() - 1] == '"') {

                token = token.substr(1, token.length() - 2);
            }
            column.push_back(token);
        }

        if(column.size() != 6) {
            LOG(0, "Cannot parse line [" << line << "]");
            continue;
        }

        char *end = nullptr;
        address_t address = std::strtoul(column[0].c_str(), &end, 16);
        if(*end) {
            LOG(0, "Cannot parse symbol address [" << column[0] << "]");
            continue;
        }

        size_t size = std::strtoul(column[1].c_str(), &end, 10);
        if(*end) {
            LOG(0, "Cannot parse symbol size [" << column[1] << "]");
            continue;
        }

        auto tag = column[2];
        auto symbolName = column[3];
        auto sourceFile = column[4];
        auto sourceLineNum = column[5];

        auto symbol = makeSymbol(address, size, tag, symbolName, list->getCount());
        if(symbol) list->add(symbol, symbol->getIndex());
    }

    LOG(0, "Found " << list->getCount() << " PE symbols");
    return list;
}

Symbol *PESymbolParser::makeSymbol(address_t address, size_t size,
    const std::string &tag, const std::string &name, size_t index) {

    size_t shndx = 0;

    Symbol::SymbolType type = Symbol::TYPE_UNKNOWN;
    Symbol::BindingType bind = Symbol::BIND_GLOBAL;
    if(tag == "SymTagData") {
        type = Symbol::TYPE_OBJECT;
        shndx = 1;  // make up an index for data section
    }
    else if(tag == "SymTagFunction") {
        type = Symbol::TYPE_FUNC;
        shndx = 2;  // make up an index for text section
    }
    else if(tag == "SymTagPublicSymbol") {
        type = Symbol::TYPE_FUNC;
        shndx = 0;  // SHN_UNDEF
    }
    else {
        LOG(0, "Unknown symbol tag [" << tag << "], type will be TYPE_UNKNOWN");
    }

    LOG(11, "    making symbol [" << name << "] at 0x" << std::hex << address
        << " size " << std::dec << size << " tag " << tag);

    char *c_name = new char[name.length() + 1];
    std::strcpy(c_name, name.c_str());

    return new Symbol(address, size, c_name, type, bind, index, shndx);
}
