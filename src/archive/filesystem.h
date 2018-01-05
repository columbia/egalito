#ifndef EGALITO_ARCHIVE_FILESYSTEM_H
#define EGALITO_ARCHIVE_FILESYSTEM_H

#include <string>

class Program;
class Module;

class ArchiveFileSystem {
private:
    std::string root;
public:
    ArchiveFileSystem(const std::string &root = ".hobbit")
        : root(root) {}

    std::string getArchivePathFor(Module *module,
        const std::string &mode = "default");
    std::string getArchivePathFor(Program *program,
        const std::string &mode = "default");
    void makeArchivePath(const std::string &archivePath);

    std::string getModuleArchivePath(const std::string &path,
        const std::string &mode = "default");
    std::string getProgramArchivePath(const std::string &path,
        const std::string &mode = "default");
    bool archivePathExists(const std::string &archivePath);
private:
    std::string getArchivePath(const std::string &mode,
        const std::string &type, const std::string &path);
    std::string canonicalPath(const std::string &filename);
};

#endif
