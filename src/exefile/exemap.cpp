#include "exemap.h"

ExeSectionImpl::ExeSectionImpl(int index, const std::string &name)
    : index(index), name(name), virtualAddress(0), readAddress(nullptr) {
}

ExeSectionImpl::ExeSectionImpl(int index, const std::string &name,
    address_t virtualAddress, char *readAddress)
    : index(index), name(name), virtualAddress(virtualAddress),
    readAddress(readAddress) {
}

address_t ExeSectionImpl::convertOffsetToVA(size_t offset) {
    return virtualAddress + offset;
}

address_t ExeSectionImpl::convertVAToOffset(address_t va) {
    return va - virtualAddress;
}

