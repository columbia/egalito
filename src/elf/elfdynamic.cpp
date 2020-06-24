#include <fstream>
#include <sstream>
#include <cstdlib>
#include <elf.h>
#include <glob.h>

#include "elfdynamic.h"
#include "elfmap.h"
#include "elfxx.h"
#include "util/feature.h"
#include "conductor/filesystem.h"

#include "log/log.h"

void ElfDynamic::parse(ElfMap *elf, Library *library) {
    auto dynamic = elf->getSectionReadPtr<unsigned long *>(".dynamic");
    if(!dynamic) return;  // statically linked
    auto strtab = elf->getDynstrtab();

    LOG(1, "examining dependencies for ELF file");

    for(unsigned long *pointer = dynamic; *pointer != DT_NULL; pointer += 2) {
        unsigned long type = pointer[0];
        unsigned long value = pointer[1];

        if(type == DT_NEEDED) {
            auto name = strtab + value;
            LOG(2, "    depends on shared library [" << name << "]");
            dependencyList.push_back(std::make_pair(name, library));
        }
        else if(type == DT_RPATH || type == DT_RUNPATH) {
	    auto rpath = strtab + value;
	    auto bin = library->getResolvedPath();
	    auto pwd = bin.substr(0, bin.rfind("/"));

	    std::string resolvedRpath(rpath);

	    auto rpos = std::string::npos;
	    while((rpos = resolvedRpath.find("$ORIGIN")) != std::string::npos) {
		resolvedRpath.replace(rpos, 7, pwd);
	    }

	    this->rpath = std::string(resolvedRpath);
            LOG(2, "    rpath [" << rpath
		<< "], resolved to:  " << resolvedRpath);
       }
    }

    resolveLibraries();
}

void ElfDynamic::addDependency(Library *library, std::string soname) {
    dependencyList.push_back(std::make_pair(soname, library));
    resolveLibraries();
}

std::string ElfDynamic::findSharedObject(std::string name) {
    setupSearchPath();

    for(auto path : searchPath) {
        std::string fullPath = path + "/" + name;
        std::ifstream file(fullPath);
        if(file.is_open() && isValidElf(file)) {
            file.close();
            return fullPath;
        }
    }
    LOG(0, "WARNING: can't find shared object ["
        << name << "] in search path");
    return "";
}

template <typename Out>
static void split(const std::string &s, char delim, Out result) {
    std::stringstream ss;
    ss.str(s);
    std::string item;
    while(std::getline(ss, item, delim)) {
        *(result++) = item;
    }
}

void ElfDynamic::setupSearchPath() {
    // make idempotent
    if(searchPath.size()) return;

    const char *egalito_library_path = getenv("EGALITO_LIBRARY_PATH");
    if(egalito_library_path) {
        split(egalito_library_path, ':', std::back_inserter(searchPath));
    }

    if(!rpath.empty()) {
        split(rpath, ':', std::back_inserter(searchPath));
    }

    const char *ld_library_path = getenv("LD_LIBRARY_PATH");
    if(ld_library_path) {
        split(ld_library_path, ':', std::back_inserter(searchPath));
    }

    int musl = isFeatureEnabled("EGALITO_MUSL");

    auto cfs = ConductorFilesystem::getInstance();
    if(musl) {
        parseMuslLdConfig(cfs->transform("/etc/ld-musl-x86_64.path"), searchPath);
    }
    else {
        parseLdConfig(cfs->transform("/etc/ld.so.conf"), searchPath);
    }
    searchPath.push_back(cfs->transform("/lib"));
    searchPath.push_back(cfs->transform("/usr/lib"));
    searchPath.push_back(cfs->transform("/lib64"));
    searchPath.push_back(cfs->transform("/usr/lib64"));
    searchPath.push_back(cfs->transform("/usr/local/musl/lib"));
}

std::vector<std::string> ElfDynamic::doGlob(std::string pattern) {
    std::vector<std::string> output;
    glob_t list;
    glob(pattern.c_str(), 0, NULL, &list);

    for(size_t i = 0; i < list.gl_pathc; i ++) {
        output.push_back(list.gl_pathv[i]);
    }

    globfree(&list);
    return std::move(output);
}

void ElfDynamic::parseMuslLdConfig(std::string filename,
    std::vector<std::string> &searchPath) {

    std::ifstream file(filename.c_str());

    std::string line;
    while(std::getline(file, line)) {
        if(line.size() == 0) continue;
        searchPath.push_back(ConductorFilesystem::getInstance()->transform(line));
    }
}

void ElfDynamic::parseLdConfig(std::string filename,
    std::vector<std::string> &searchPath) {

    std::ifstream file(filename.c_str());
    std::string line;
    while(std::getline(file, line)) {
        if(line.size() == 0) continue;
        if(line[0] == '#') continue;

        std::vector<std::string> tokens;
        split(line, ' ', std::back_inserter(tokens));
        if(tokens.size() == 0) continue;
        else if(tokens.size() == 1) {
            searchPath.push_back(
                ConductorFilesystem::getInstance()->transform(tokens[0]));
        }
        else if(tokens[0] == "include") {
            std::vector<std::string> files = doGlob(
                ConductorFilesystem::getInstance()->transform(tokens[1]));
            for(auto f : files) {
                parseLdConfig(f, searchPath);
            }
        }
        else {
            LOG(0, "Unrecognized line in LD config: [" << line << "]");
        }
    }
}

bool ElfDynamic::isValidElf(std::ifstream &file) {
    ElfXX_Ehdr header;
    file.read((char *)&header, sizeof(header));

    // make sure this is an ELF file
    if(*(ElfXX_Word *)&header != *(ElfXX_Word *)ELFMAG) {
        return false;
    }

    // check architecture type
    char type = ((char *)&header)[EI_CLASS];
    if(type != ELFCLASSXX) {
        return false;
    }

    return true;
}

void ElfDynamic::resolveLibraries() {
    setupSearchPath();
    for(auto &pair : dependencyList) {
        auto library = pair.first;
        auto sharedLib = pair.second;
        if(library[0] == '/') {
            LOG(3, "    library at [" << library << "]");
            processLibrary(library,
                library.substr(library.rfind('/') + 1), sharedLib);
            continue;
        }

        std::string fullPath = findSharedObject(library);
        processLibrary(fullPath, library, sharedLib);
    }
}

void ElfDynamic::processLibrary(const std::string &fullPath,
    const std::string &filename, Library *depend) {

    if(filename == "ld-linux-x86-64.so.2"
        || filename == "ld-linux-aarch64.so.1"
        || filename == "ld-linux-riscv64-lp64d.so.1") {

        LOG(2, "    skipping processing of ld.so for now");
        return;
    }
    if(!isFeatureEnabled("EGALITO_USE_DISASM")) {
        if(filename == "libcapstone.so.4" || filename == "libcapstone.so.3") {
            LOG(2, "    skipping processing of disassembly libraries");
            return;
        }
    }

    // don't process this library again if already done
    if(auto library = libraryList->find(filename)) {
        if(depend) depend->addDependency(library);
        return;
    }

    LOG(2, "    process [" << fullPath << "] a.k.a. " << filename);

    //ElfMap *elf = new ElfMap(fullPath.c_str());
    auto library = new Library(filename, Library::guessRole(filename));
    library->setResolvedPath(fullPath);
    libraryList->add(library);

    if(depend) depend->addDependency(library);

    LOG(2, "    added new library [" << filename << "]");
}
