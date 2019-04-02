#include <iostream>
#include <sstream>
#include <cstdlib>
#include "command.h"

const char *ArgumentSpec::getExpectedMessage(ArgumentType type) {
    switch(type) {
    case TYPE_NOTHING:
    case TYPE_FLAG:
        return "expected no subsequent value";
    case TYPE_BOOL:
        return "expected bool i.e. one of {0,1,false,true}";
    case TYPE_STRING:
        return "expected string";
    case TYPE_FILENAME:
        return "expected valid filename";
    case TYPE_VARIABLE:
        return "expected variable name with leading $";
    case TYPE_ADDRESS:
        return "expected address e.g. 0x1000";
    case TYPE_HEX:
        return "expected hex number e.g. 0x1000";
    case TYPE_DECIMAL:
        return "expected decimal number e.g. 99";
    case TYPE_NUMBER:
        return "expected number e.g. 99 or 0x1000";
    case TYPE_UNSIGNED_NUMBER:
        return "expected unsigned number e.g. 99 or 0x1000";
    case TYPE_CHUNK:
        return "expected name of chunk e.g. _start";
    case TYPE_MODULE:
        return "expected name of module e.g. module-(executable)";
    case TYPE_FUNCTION:
        return "expected name of function e.g. _start";
    case TYPE_PASS:
        return "expected name of chunk pass";
    case TYPE_ANYTHING:
        return nullptr;
    }
    return nullptr;
}

const char *ArgumentSpec::getTypeName(ArgumentType type) {
    switch(type) {
    case TYPE_NOTHING:          return "NOTHING";
    case TYPE_FLAG:             return "FLAG";
    case TYPE_BOOL:             return "BOOL";
    case TYPE_STRING:           return "STRING";
    case TYPE_FILENAME:         return "FILENAME";
    case TYPE_VARIABLE:         return "VARIABLE";
    case TYPE_ADDRESS:          return "ADDRESS";
    case TYPE_HEX:              return "HEX";
    case TYPE_DECIMAL:          return "DECIMAL";
    case TYPE_NUMBER:           return "NUMBER";
    case TYPE_UNSIGNED_NUMBER:  return "UNSIGNED_NUMBER";
    case TYPE_CHUNK:            return "CHUNK";
    case TYPE_MODULE:           return "MODULE";
    case TYPE_FUNCTION:         return "FUNCTION";
    case TYPE_PASS:             return "PASS";
    case TYPE_ANYTHING:         return "ANYTHING";
	default:				    return "";
	}
    return "";
}

#define CHECK_STR_TO_INT(data, strtoX, base) do { \
        const char *str = data.c_str(); \
        char *end = nullptr; \
        strtoX(str, &end, base); \
        return (*str != 0 && end && *end == 0); \
    } while(0)
bool ArgumentSpec::flagValueMatches(const std::string &data) const {
    switch(type) {
    case TYPE_NOTHING:
    case TYPE_FLAG:
        throw "Please call ArgumentSpec::hasFlagValue()";
    case TYPE_BOOL:
        return (data == "0" || data == "1" || data == "false" || data == "true");
    case TYPE_STRING:
    case TYPE_FILENAME:
        return true;
    case TYPE_VARIABLE:
        return data.length() >= 2 && data[0] == '$';
    case TYPE_ADDRESS:
        CHECK_STR_TO_INT(data, std::strtoul, 16);
    case TYPE_HEX:
        CHECK_STR_TO_INT(data, std::strtol, 16);
    case TYPE_DECIMAL:
        CHECK_STR_TO_INT(data, std::strtol, 10);
    case TYPE_NUMBER:
        CHECK_STR_TO_INT(data, std::strtol, 0);
    case TYPE_UNSIGNED_NUMBER:
        CHECK_STR_TO_INT(data, std::strtoul, 0);
    case TYPE_CHUNK:
    case TYPE_MODULE:
    case TYPE_FUNCTION:
    case TYPE_PASS:
    case TYPE_ANYTHING:
        return true;
    }
    return false;
}

bool ArgumentSpec::flagNameMatches(const std::string &data) const {
    auto it = flagList.find(data);
    return it != flagList.end();
}

ArgumentSpecList::ArgumentSpecList(const std::map<std::string, ArgumentSpec> &flagSpec,
    const std::vector<ArgumentSpec> &indexSpec, size_t requiredArguments,
    bool supportsInStream)
    : supportsInStream(supportsInStream), flagSpec(flagSpec),
    indexSpec(indexSpec), requiredArguments(requiredArguments) {
    
}

std::string ArgumentValue::getString() const {
    return data;
}

bool ArgumentValue::getBool() const {
    switch(type) {
    case ArgumentSpec::TYPE_FLAG:
        return true;  // if the argument exists, flag is true
    case ArgumentSpec::TYPE_BOOL:
        if(data == "0") return false;
        if(data == "1") return true;
        if(data == "false") return false;
        if(data == "true") return true;
        throw std::string("Invalid argument, ") + ArgumentSpec::getExpectedMessage(type);
    default:
        throw "Calling ArgumentValue::getBool() on unexpected argument type";
    }
}

#define STR_TO_INT(data, strtoX, base) do { \
        const char *str = data.c_str(); \
        char *end = nullptr; \
        auto value = strtoX(str, &end, base); \
        if(*str != 0 && end && *end == 0) return value; \
    } while(0)
address_t ArgumentValue::getAddress() const {
    switch(type) {
    case ArgumentSpec::TYPE_ADDRESS:
    case ArgumentSpec::TYPE_HEX: {
        /*const char *str = data.c_str();
        char *end = nullptr;
        address_t address = std::strtoul(str, &end, 16);
        if(*str != 0 && *end == 0) return address;*/
        STR_TO_INT(data, std::strtoul, 16);
        throw std::string("Invalid argument, ") + ArgumentSpec::getExpectedMessage(type);
    }
    default:
        throw "Calling ArgumentValue::getAddress() on unexpected argument type";
    }
}

long ArgumentValue::getNumber() const {
    switch(type) {
    case ArgumentSpec::TYPE_ADDRESS:
    case ArgumentSpec::TYPE_HEX: {
        STR_TO_INT(data, std::strtol, 16);
        throw std::string("Invalid argument, ") + ArgumentSpec::getExpectedMessage(type);
    }
    case ArgumentSpec::TYPE_DECIMAL: {
        STR_TO_INT(data, std::strtol, 10);
        throw std::string("Invalid argument, ") + ArgumentSpec::getExpectedMessage(type);
    }
    case ArgumentSpec::TYPE_NUMBER: {
        STR_TO_INT(data, std::strtol, 0);
        throw std::string("Invalid argument, ") + ArgumentSpec::getExpectedMessage(type);
    }
    default:
        throw "Calling ArgumentValue::getNumber() on unexpected argument type";
    }
}

unsigned long ArgumentValue::getUnsignedNumber() const {
    switch(type) {
    case ArgumentSpec::TYPE_ADDRESS:
    case ArgumentSpec::TYPE_HEX: {
        STR_TO_INT(data, std::strtoul, 16);
        throw std::string("Invalid argument, ") + ArgumentSpec::getExpectedMessage(type);
    }
    case ArgumentSpec::TYPE_DECIMAL: {
        STR_TO_INT(data, std::strtoul, 10);
        throw std::string("Invalid argument, ") + ArgumentSpec::getExpectedMessage(type);
    }
    case ArgumentSpec::TYPE_NUMBER: {
        STR_TO_INT(data, std::strtoul, 0);
        throw std::string("Invalid argument, ") + ArgumentSpec::getExpectedMessage(type);
    }
    default:
        throw "Calling ArgumentValue::getUnsignedNumber() on unexpected argument type";
    }
}

Chunk *ArgumentValue::getChunk(EgalitoInterface *egalito) const {
    switch(type) {
    case ArgumentSpec::TYPE_CHUNK:
    case ArgumentSpec::TYPE_MODULE:
    case ArgumentSpec::TYPE_FUNCTION:
        return nullptr;
    default:
        throw "Calling ArgumentValue::getChunk() on unexpected argument type";
    }
}

bool ArgumentValueList::hasArgument(const std::string &name) const {
    return flag.find(name) != flag.end();
}

bool ArgumentValueList::getBool(const std::string &name, bool defaultValue) const {
    auto it = flag.find(name);
    return (it == flag.end() ? defaultValue : (*it).second.getBool());
}

std::string ArgumentValueList::getString(const std::string &name,
    const std::string &defaultValue) const {

    auto it = flag.find(name);
    return (it == flag.end() ? defaultValue : (*it).second.getString());
}

long ArgumentValueList::getNumber(const std::string &name,
    long defaultValue) const {

    auto it = flag.find(name);
    return (it == flag.end() ? defaultValue : (*it).second.getNumber());
}

const ArgumentValue &ArgumentValueList::get(const std::string &name,
    const ArgumentValue &defaultValue) const {

    auto it = flag.find(name);
    return (it == flag.end() ? defaultValue : (*it).second);
}

void ArgumentValueList::dump() {
    for(auto kv : flag) {
        std::cout << kv.first << " " << kv.second.getType() << std::endl;
    }
}
