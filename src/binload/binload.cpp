#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <fstream>
#include <cstring>

#include "types.h"

#undef DEBUG_GROUP
#define DEBUG_GROUP load
#include "log/log.h"

extern address_t entry;
extern "C" void _start2(void);

#define TEMPORARY_FILE  "bintest-tmp.bin"

#define ROUND_DOWN(x)   ((x) & ~0xfff)
#define ROUND_UP(x)     (((x) + 0xfff) & ~0xfff)

// this has to be adjusted manually
#define TOP_ADDRESS             0xC400000

#define MAP_START_ADDRESS       (ROUND_DOWN(TOP_ADDRESS))
#define MAP_OFFSET              (TOP_ADDRESS - MAP_START_ADDRESS)

int main(int argc, char **argv) {
    if(argc < 3) {
        return -1;
    }

    int fd = open(argv[1], O_RDONLY);
    auto length = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    int prot = PROT_READ | PROT_WRITE | PROT_EXEC;

    entry = strtol(argv[2], NULL, 0);
    auto size = ROUND_UP(length + MAP_OFFSET);
    auto map = mmap((void *)MAP_START_ADDRESS, size, prot, MAP_PRIVATE, fd, 0);
    if(map == (void *)-1) {
        LOG(1, "out of memory?");
        return -1;
    }
    if(map != (void *)MAP_START_ADDRESS) {
        LOG(1, "overlapping with other regions");
        return -1;
    }

    // bss should be really cleared by the target binary,
    // but for this fake loader, we may need to map extra pages

    _start2();

    return 0;
}
