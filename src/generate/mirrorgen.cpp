#include "mirrorgen.h"
#include "modulegen.h"
#include "data.h"
#include "concrete.h"

MirrorGen::MirrorGen(Program *program, SandboxBacking *backing)
    : ElfGeneratorImpl(program, backing) {

    getConfig()->setDynamicallyLinked(true);
    getConfig()->setPositionIndependent(true);
}

void MirrorGen::preCodeGeneration() {
    ElfPipeline pipeline(getData(), getConfig());
    pipeline.add(new BasicElfCreator());
    pipeline.add(new MakeInitArray(/*stage=*/ 0));  // !AssignSectionsToSegments
    pipeline.add(new MakeGlobalPLT());
    pipeline.add(new BasicElfStructure(/*addLibDependencies=*/ true));
    pipeline.add(new AssignSectionsToSegments());
    pipeline.execute();
}

void MirrorGen::afterAddressAssign() {
    ElfPipeline pipeline(getData(), getConfig());
    pipeline.addDependency("BasicElfStructure");
    pipeline.add(new MakeInitArray(/*stage=*/ 1));  // AssignSectionsToSegments
    pipeline.add(new UpdatePLTLinks());
    pipeline.add(new CopyDynsym());
    pipeline.add(new MakeGlobalSymbols());
    pipeline.execute();
}

void MirrorGen::generateContent(const std::string &filename) {
    ElfPipeline pipeline(getData(), getConfig());
    pipeline.addDependency("AssignSectionsToSegments");

    for(auto module : CIter::children(getData()->getProgram())) {
        ModuleGen::Config config;
        config.setUniqueSectionNames(false);
        config.setRelocsForAbsoluteRefs(true);
        config.setCodeBacking(dynamic_cast<MemoryBufferBacking *>
            (getData()->getBacking()));
        auto moduleGen = ModuleGen(config, module, getData()->getSectionList());
        moduleGen.makeDataSections();
        moduleGen.makeTextAccumulative();
        if(true || module->getLibrary()->getRole() == Library::ROLE_LIBC) {
            moduleGen.makeTLS();
        }
    }
    pipeline.add(new MakeDynsymHash());  // after all .dynsym entries added
    pipeline.add(new TextSectionCreator());
    pipeline.add(new GenerateSectionTable());
    pipeline.add(new ElfFileWriter(filename));

    pipeline.execute();
}
