#ifndef EGALITO_SANDBOX_H
#define EGALITO_SANDBOX_H

#include <vector>
#include <new>
#include <string>
#include "types.h"
#include "elf/elfspace.h"

#define MAX_SANDBOX_SIZE (16 * 0x1000 * 0x1000)

class Slot {
private:
    address_t address;
    size_t available;
public:
    Slot(address_t address, size_t size)
        : address(address), available(size) {}
    uint8_t *read() { return 0; }
    bool append(uint8_t *data, size_t size);
    address_t getAddress() const { return address; }
};

class SandboxBacking {
private:
    size_t size;
    size_t memSize;
public:
    SandboxBacking(size_t size) : size(size) {}

    address_t getBase() const;
    size_t getSize() const { return size; }
    size_t getMemorySize() const { return memSize; }
};

class MemoryBacking : public SandboxBacking {
private:
    address_t base;
public:
    /** May throw std::bad_alloc. */
    MemoryBacking(address_t address, size_t size);
    /*MemoryBacking(const MemoryBacking &other)
        : SandboxBacking(other.getSize()), base(other.base) {}*/
    address_t getBase() const { return base; }

    void finalize();
    bool reopen();
    void recreate(address_t end);
};

class MemoryBufferBacking : public SandboxBacking {
private:
    address_t base;
    std::string buffer;
public:
    MemoryBufferBacking(address_t address, size_t size);

    address_t getBase() const { return base; }
    std::string &getBuffer() { return buffer; }

    void finalize();
    bool reopen();
    bool recreate();
};

class ExeBacking : public MemoryBacking {
private:
    ElfSpace *elfSpace;
    std::string filename;
public:
    ExeBacking(ElfSpace *elfSpace, std::string filename);

    void finalize();
    bool reopen() { return false; }
};

class ObjBacking : public MemoryBacking {
private:
    ElfSpace *elfSpace;
    std::string filename;
public:
    ObjBacking(ElfSpace *elfSpace, std::string filename);

    void finalize();
    bool reopen() { return false; }
};

class Module;
class AnyGenerateBacking : public MemoryBufferBacking {
private:
    Module *module;
    std::string filename;
public:
    AnyGenerateBacking(Module *module, std::string filename);

    void finalize();
    bool reopen() { return false; }
};

template <typename Backing>
class SandboxAllocator {
protected:
    Backing *backing;
public:
    SandboxAllocator(Backing *backing) : backing(backing) {}

    /** May throw std::bad_alloc. */
    Slot allocate(size_t request);
};

template <typename Backing>
class WatermarkAllocator : public SandboxAllocator<Backing> {
private:
    address_t base;
    address_t watermark;
public:
    WatermarkAllocator(Backing *backing) : SandboxAllocator<Backing>(backing),
        base(backing->getBase()), watermark(backing->getBase()) {}

    Slot allocate(size_t request);
    address_t getCurrent() const { return watermark; }
    void reset() { watermark = base; }
};

template <typename Backing>
Slot WatermarkAllocator<Backing>::allocate(size_t request) {
    size_t max = this->backing->getBase() + this->backing->getSize();

    if(watermark + request > max) {
        throw std::bad_alloc();
    }

    address_t region = watermark;
    watermark += request;
    return Slot(region, request);
}

class Sandbox {
public:
    virtual ~Sandbox() {}

    /** May throw std::bad_alloc. */
    virtual Slot allocate(size_t request) = 0;
    virtual void finalize() = 0;
    virtual bool reopen() = 0;

    virtual SandboxBacking *getBacking() = 0;
};

template <typename T> struct id { typedef T type; };

template <typename Backing, typename Allocator>
class SandboxImpl : public Sandbox {
private:
    Backing backing;
    Allocator alloc;
public:
    SandboxImpl(const Backing &backing)
        : backing(backing), alloc(Allocator(&this->backing)) {}

    virtual Slot allocate(size_t request)
        { return alloc.allocate(request); }
    virtual void finalize() { backing.finalize(); }
    virtual bool reopen() { return backing.reopen(); }

    void recreate() { recreate(id<Backing>()); }
    virtual SandboxBacking *getBacking() { return &backing; }

private:
    void recreate(id<MemoryBacking>);
};

template <typename Backing, typename Allocator>
void SandboxImpl<Backing, Allocator>::recreate(id<MemoryBacking>) {
    backing.recreate(alloc.getCurrent());
    alloc.reset();
}

template <typename SandboxImplType>
class DualSandbox : public Sandbox {
private:
    SandboxImplType *sandbox[2];
    size_t i;

public:
    DualSandbox(SandboxImplType *one, SandboxImplType *other)
        : sandbox{one, other}, i(0) {}
    void flip() { i^= 1; }
    //Sandbox *get() const { return sandbox[i]; }

    virtual Slot allocate(size_t request)
        { return sandbox[i]->allocate(request); }
    virtual void finalize() { sandbox[i]->finalize(); }
    virtual bool reopen() { return sandbox[i]->reopen(); }
    void recreate() const { sandbox[i]->recreate(); }
    virtual SandboxBacking *getBacking() { return sandbox[i]->getBacking(); }
};

using ShufflingSandbox = DualSandbox<
    SandboxImpl<MemoryBacking, WatermarkAllocator<MemoryBacking>>>;

#endif
