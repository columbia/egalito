#include "kernelgen.h"
#include "modulegen.h"
#include "data.h"
#include "concrete.h"
#include "chunk/concrete.h"

KernelGen::KernelGen(Program *program, SandboxBacking *backing)
    : ElfGeneratorImpl(program, backing) {

    getConfig()->setFreestandingKernel(true);
}

void KernelGen::preCodeGeneration() {
    ElfPipeline pipeline(getData(), getConfig());
    pipeline.add(new BasicElfCreator(/*makeInitArray = */ false));
    pipeline.add(new BasicElfStructure());
    pipeline.add(new AssignSectionsToSegments());
    pipeline.execute();
}

void KernelGen::afterAddressAssign() {
    ElfPipeline pipeline(getData(), getConfig());
    pipeline.addDependency("BasicElfStructure");
    pipeline.execute();
}

void KernelGen::generateContent(const std::string &filename) {
    ElfPipeline pipeline(getData(), getConfig());
    pipeline.addDependency("AssignSectionsToSegments");

    for(auto module : CIter::children(getData()->getProgram())) {
        ModuleGen::Config config;
        config.setFreestandingKernel(true);
        config.setUniqueSectionNames(true);
        config.setCodeBacking(dynamic_cast<MemoryBufferBacking *>
            (getData()->getBacking()));
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
