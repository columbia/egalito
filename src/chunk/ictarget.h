#ifndef EGALITO_CHUNK_ICTARGET_H
#define EGALITO_CHUNK_ICTARGET_H

#include<string>
using namespace std;

#include "chunk/chunk.h"


class IndirectCallTarget : public ChunkImpl {

	private :
		address_t address;
		string name;
		bool global;
		bool unknown;

	public:
		IndirectCallTarget() : address(0),global(false),unknown(false) {}
		IndirectCallTarget(address_t address);
		void setName(string str);
		void setGlobal();
		void setUnknown();
		string getName();
		bool isGlobal();
		bool isUnknown();


		virtual void accept(ChunkVisitor *visitor) {}
		virtual address_t getAddress();
		virtual void setAddress(address_t address);
};
#endif
