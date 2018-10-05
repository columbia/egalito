#include "uniongen.h"
#include "modulegen.h"
#include "data.h"
#include "concrete.h"

void UnionGen::preCodeGeneration() {
    ElfPipeline pipeline(getData(), getConfig());
    pipeline.add(new BasicElfCreator());
    pipeline.add(new BasicElfStructure());
    pipeline.execute();
}

void UnionGen::afterAddressAssign() {
    ElfPipeline pipeline(getData(), getConfig());
    pipeline.addDependency("BasicElfStructure");
    pipeline.add(new MakeInitArray());
    pipeline.add(new AssignSectionsToSegments());
    pipeline.execute();
}

void UnionGen::generateContent(const std::string &filename) {
    ElfPipeline pipeline(getData(), getConfig());
    pipeline.addDependency("AssignSectionsToSegments");

    for(auto module : CIter::children(getData()->getProgram())) {
        ModuleGen::Config config;
        config.setUniqueSectionNames(true);
        config.setCodeBacking(getData()->getBacking());
        auto moduleGen = ModuleGen(config, module, getData()->getSectionList());
        moduleGen.makeDataSections();
        moduleGen.makeTextAccumulative();
        if(module->getLibrary()->getRole() == Library::ROLE_LIBC) {
            moduleGen.makeTLS();
        }
    }
    pipeline.add(new TextSectionCreator());
    pipeline.add(new GenerateSectionTable());
    pipeline.add(new ElfFileWriter(filename));

    pipeline.execute();
}
