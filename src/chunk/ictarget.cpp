#include "ictarget.h"



IndirectCallTarget::IndirectCallTarget(address_t address) : address(address),global(false),unknown(false) { }

address_t IndirectCallTarget::getAddress() {
	return address;
}

void IndirectCallTarget::setAddress(address_t address) {
	this->address = address;
}

void IndirectCallTarget::setName(string str) {
	name = str;
}

string IndirectCallTarget::getName() {
	return name;
}

void IndirectCallTarget::setGlobal() {
	global = true;
}

void IndirectCallTarget::setUnknown() {
	unknown = true;
}

bool IndirectCallTarget::isGlobal() {
	return global;
}

bool IndirectCallTarget::isUnknown() {
	return unknown;
}
