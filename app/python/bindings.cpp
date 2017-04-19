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

BOOST_PYTHON_MODULE(python_egalito) {
    register_exception_translator<const char *>([] (const char *s) {
        PyErr_SetString(PyExc_RuntimeError, s);
    });
    register_exception_translator<std::string>([] (const std::string &s) {
        PyErr_SetString(PyExc_RuntimeError, s.c_str());
    });

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

	class_<Symbol>("Symbol",
            init<address_t, size_t, const char *,
                Symbol::SymbolType, Symbol::BindingType,
                size_t, size_t>())
		.def("get_name", &Symbol::getName);

	class_<Function>("Function", init<Symbol *>())
		.def("get_name", &Function::getName)
		.def("accept",  &Function::accept);

	class_<Conductor>("Conductor");

	class_<ConductorSetup>("ConductorSetup")
		.def("parse_elf_files",            &ConductorSetup::parseElfFiles)
		.def("get_conductor",              &ConductorSetup::getConductor, return_internal_reference<>())
		.def("make_loader_sandbox",        &ConductorSetup::makeLoaderSandbox)
		.def("move_code_assign_addresses", &ConductorSetup::moveCodeAssignAddresses);

	class_<ChunkVisitor, boost::noncopyable>("ChunkVisitor", no_init);

	class_<ChunkDumper, bases<ChunkVisitor> >("ChunkDumper");

	class_<ChunkFind2>("ChunkFind2", init<Conductor *>())
		.def("find_function",            &ChunkFind2::findFunction,
            arg("module")=NULL, return_value_policy<reference_existing_object>())
		.def("find_function_containing", &ChunkFind2::findFunctionContaining,
            return_value_policy<reference_existing_object>());

}
