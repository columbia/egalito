#include <iomanip>
#include <sstream>
#include <ctype.h>
#include <limits.h>

#include <fcntl.h>  // for open
#include <unistd.h>  // for close
#include <sys/stat.h>
#include <sys/types.h>

#include "filesystem.h"
#include "chunk/program.h"
#include "chunk/module.h"
#include "chunk/library.h"
#include "util/streamasstring.h"
#include "log/log.h"

std::string ArchiveFileSystem::getArchivePathFor(Module *module,
    const std::string &mode) {

    auto path = module->getLibrary()->getResolvedPath();
    auto output = getArchivePath(mode, "module", path);
    LOG(0, "path for [" << module->getName() << "] is [" << output << "]");
    return output;
}

std::string ArchiveFileSystem::getArchivePathFor(Program *program,
    const std::string &mode) {

    auto path = program->getFirst()->getLibrary()->getResolvedPath();
    auto output = getArchivePath(mode, "program", path);
    LOG(0, "program path is [" << output << "]");
    return output;
}

void ArchiveFileSystem::makeArchivePath(const std::string &archivePath) {
    // make all parent directories needed for archivePath
    std::string::size_type i = 0;
    for(;;) {
        i = archivePath.find('/', i + 1);
        if(i == std::string::npos) break;

        std::string fragment = archivePath.substr(0, i);
        // use mode = 0700 for archive directories, ignore errors
        mkdir(fragment.c_str(), 0700);
    }
}

std::string ArchiveFileSystem::getModuleArchivePath(const std::string &path,
    const std::string &mode) {

    return getArchivePath(mode, "module", path);
}

std::string ArchiveFileSystem::getProgramArchivePath(const std::string &path,
    const std::string &mode) {

    return getArchivePath(mode, "program", path);
}

bool ArchiveFileSystem::archivePathExists(const std::string &archivePath) {
    int fd = open(archivePath.c_str(), O_RDONLY);
    if(fd == -1) return false;

    close(fd);
    return true;
}

std::string ArchiveFileSystem::getArchivePath(const std::string &mode,
    const std::string &type, const std::string &path) {

    StreamAsString ss;
    ss << root << '/' << mode << '/' << type << '/'
        << canonicalPath(path) << ".ega";
    return ss;
}

std::string ArchiveFileSystem::canonicalPath(const std::string &filename) {
    char buffer[PATH_MAX];
    if(!realpath(filename.c_str(), buffer)) {
        LOG(0, "error resolving real path for [" << filename << "]");
        buffer[0] = 0;
    }
    return buffer;
}
