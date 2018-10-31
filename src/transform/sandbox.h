#ifndef EGALITO_TRANSFORM_SANDBOX_H
#define EGALITO_TRANSFORM_SANDBOX_H

#include <vector>
#include <new>
#include <string>
#include "slot.h"
#include "types.h"
#include "elf/elfspace.h"

#define MAX_SANDBOX_SIZE (16 * 0x1000 * 0x1000)

class SandboxBacking {
public:
    virtual ~SandboxBacking() {}

    virtual address_t getBase() const = 0;
    virtual std::string &getBuffer() = 0;
    virtual size_t getSize() const = 0;
    virtual bool supportsDirectWrites() const = 0;

    virtual void finalize() = 0;
    virtual bool reopen() = 0;
    virtual void recreate() = 0;
};

class SandboxBackingImpl : public SandboxBacking {
private:
    address_t base;
    size_t size;
public:
    SandboxBackingImpl(address_t base, size_t size) : base(base), size(size) {}

    virtual address_t getBase() const { return base; }
    virtual std::string &getBuffer()
        { throw "SandboxBackingImplt::getBuffer() is unimplemented"; }
    virtual size_t getSize() const { return size; }
    virtual bool supportsDirectWrites() const = 0;
protected:
    void setBase(address_t base) { this->base = base; }
};

// Mapped at final base address, can directly write to mem addresses.
class MemoryBacking : public SandboxBackingImpl {
public:
    /** May throw std::bad_alloc. */
    MemoryBacking(address_t address, size_t size);

    virtual bool supportsDirectWrites() const { return true; }

    virtual void finalize();
    virtual bool reopen();
    virtual void recreate();
};

// Not mapped at final address, please write into the buffer instead.
class MemoryBufferBacking : public SandboxBackingImpl {
private:
    std::string buffer;
public:
    // Ensure that address is already mapped before calling this function
    MemoryBufferBacking(address_t address, size_t size);

    virtual std::string &getBuffer() { return buffer; }
    virtual bool supportsDirectWrites() const { return false; }

    virtual void finalize();
    virtual bool reopen();
    virtual void recreate();
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
    WatermarkAllocator(Backing *backing)
        : SandboxAllocator<Backing>(backing),
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

template <typename Backing>
class AlignedWatermarkAllocator : public SandboxAllocator<Backing> {
private:
    address_t base;
    address_t watermark;
    size_t alignment;
public:
    AlignedWatermarkAllocator(Backing *backing, size_t alignment
#ifdef ARCH_X86_64
            = 0x10  // 16-byte alloc size alignment for functions
#else
            = 0x1
#endif
        )
        : SandboxAllocator<Backing>(backing),
        base(backing->getBase()), watermark(backing->getBase()),
        alignment(alignment) {}

    Slot allocate(size_t request);
    address_t getCurrent() const { return watermark; }
    void reset() { watermark = base; }
};

template <typename Backing>
Slot AlignedWatermarkAllocator<Backing>::allocate(size_t request) {
    request = (request + alignment-1) & ~(alignment-1);

    size_t max = this->backing->getBase() + this->backing->getSize();
    if(watermark + request > max) {
        throw std::bad_alloc();
    }

    //watermark = (watermark + alignment - 1) & ~(alignment - 1);
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
    virtual bool supportsDirectWrites() const = 0;
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
    virtual bool supportsDirectWrites() const
        { return backing.supportsDirectWrites(); }

private:
    void recreate(id<MemoryBacking>);
};

template <typename Backing, typename Allocator>
void SandboxImpl<Backing, Allocator>::recreate(id<MemoryBacking>) {
    backing.recreate(/*alloc.getCurrent()*/);
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
    virtual bool supportsDirectWrites() const
        { return sandbox[i]->supportsDirectWrites(); }
};

using ShufflingSandbox = DualSandbox<
    SandboxImpl<MemoryBacking, WatermarkAllocator<MemoryBacking>>>;

/*class SandboxBuilder {
public:
    Sandbox *makeLoaderSandbox();
    ShufflingSandbox *makeShufflingSandbox();
    Sandbox *makeFileSandbox(const char *outputFile);
    Sandbox *makeStaticExecutableSandbox(const char *outputFile);
};*/

#endif
