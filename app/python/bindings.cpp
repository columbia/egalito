#include <boost/python.hpp>
#include "conductor/setup.h"

BOOST_PYTHON_MODULE(python_egalito)
{
	using namespace boost::python;

 class_<ConductorSetup>("ConductorSetup")
		.def("parseElfFiles", &ConductorSetup::parseElfFiles);
}
