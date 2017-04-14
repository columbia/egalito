#include <boost/python.hpp>
#include "conductor/setup.h"
#include "operation/find2.h"
#include "conductor/conductor.h"
#include "elf/symbol.h"
#include "chunk/chunkfwd.h"
#include "chunk/dump.h"
#include "chunk/visitor.h"
#include "types.h"

using namespace boost::python;


BOOST_PYTHON_MODULE(python_egalito)
{
	enum_<Symbol::SymbolType>("SymbolType")
		.value("FUNC",    Symbol::SymbolType::TYPE_FUNC)
		.value("IFUNC",   Symbol::SymbolType::TYPE_IFUNC)
		.value("OBJECT",  Symbol::SymbolType::TYPE_OBJECT)
		.value("SECTION", Symbol::SymbolType::TYPE_SECTION)
		.value("FILE",    Symbol::SymbolType::TYPE_FILE)
		.value("UNKNOWN", Symbol::SymbolType::TYPE_UNKNOWN);

	enum_<Symbol::BindingType>("SymbolType")
		.value("LOCAL",  Symbol::BindingType::BIND_LOCAL)
		.value("GLOBAL", Symbol::BindingType::BIND_GLOBAL)
		.value("WEAK",   Symbol::BindingType::BIND_WEAK);


	class_<Symbol>("Symbol", init<
								 address_t, size_t,
								 const char *,
								 Symbol::SymbolType,
								 Symbol::BindingType,
								 size_t,
								 size_t>())
		.def("getName", &Symbol::getName);

	class_<Function>("Function", init<Symbol *>())
		.def("getName", &Function::getName)
		.def("accept",  &Function::accept);

	class_<Conductor>("Conductor");

	class_<ConductorSetup>("ConductorSetup")
		.def("parseElfFiles",           &ConductorSetup::parseElfFiles)
		.def("getConductor",            &ConductorSetup::getConductor, return_value_policy<manage_new_object>())
		.def("makeLoaderSandbox",       &ConductorSetup::makeLoaderSandbox)
		.def("moveCodeAssignAddresses", &ConductorSetup::moveCodeAssignAddresses);

	class_<ChunkVisitor, boost::noncopyable>("ChunkVisitor", no_init);

	class_<ChunkDumper, bases<ChunkVisitor> >("ChunkDumper");

	class_<ChunkFind2>("ChunkFind2", init<Conductor *>())
		.def("findFunction", &ChunkFind2::findFunction,
				 arg("module")=NULL, return_value_policy<manage_new_object>());

}
