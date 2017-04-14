#include <cstring>

#include "framework/include.h"
#include "disasm/disassemble.h"
#include "instr/isolated.h"

TEST_CASE("Disassemble Instruction", "[disasm][ins]") {
	Instruction *ins;

#ifdef ARCH_X86_64
	// add #0, %eax
	std::vector<uint8_t> bytes = {0x83, 0xc0, 0x00};
#elif defined(ARCH_AARCH64)
	// add X0, X0, #0
	std::vector<uint8_t> bytes = {0x00, 0x00, 0x00, 0x91};
#elif defined(ARCH_ARM)
	//add r0, r0, #0
	std::vector<uint8_t> bytes = {0x00, 0x00, 0x80, 0xe2};
#endif

	ins = Disassemble::instruction(bytes, true, 0);
	DisassembledInstruction *disasmIns = static_cast<DisassembledInstruction *>(ins->getSemantic());

	const char *expectedBytes = reinterpret_cast<const char *>(bytes.data());
	const char *actualBytes = disasmIns->getAssembly()->getBytes();

	CHECK(std::memcmp(expectedBytes, actualBytes, bytes.size()) == 0);

}
