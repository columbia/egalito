#ifndef EGALITO_SANDBOX_H
#define EGALITO_SANDBOX_H

#include <vector>
#include <new>

#define MAX_SANDBOX_SIZE (100 * 0x1000 * 0x1000)

class Slot {
private:
    address_t address;
    size_t available;
public:
    Slot(address_t address, size_t size)
        : address(address), available(size) {}
    uint8_t *read() { return 0; }
    bool append(uint8_t *data, size_t size);
};

class AnyLengthSlot {
private:
    std::vector<uint8_t> buffer;
public:
    uint8_t *read() { return buffer.data(); }
    bool append(uint8_t *data, size_t size);
};

class ReadOnlySlot {
private:
    uint8_t *address;
public:
    ReadOnlySlot(uint8_t *address) : address(address) {}

    uint8_t *read() { return address; }
    bool append(uint8_t *data, size_t size) { return false; }
};

class SandboxBacking {
private:
    size_t size;
public:
    SandboxBacking(size_t size) : size(size) {}

    address_t getBase() const;
    size_t getSize() const { return size; }

    void finalize();
};

class MemoryBacking : public SandboxBacking {
private:
    address_t base;
public:
    MemoryBacking(size_t size) throw std::bad_alloc;
    address_t getBase() const { return base; }

    void finalize();
};

class ELFBacking : public MemoryBacking {
private:
    std::string filename;
public:
    ELFBacking(std::string filename);

    void finalize();
};

class SandboxAllocator {
protected:
    SandboxBacking *backing;
public:
    SandboxAllocator(SandboxBacking *backing) : backing(backing) {}
    Slot allocate(size_t request) throw std::bad_alloc;
};

class WatermarkAllocator : public SandboxAllocator {
private:
    address_t watermark;
public:
    WatermarkAllocator(SandboxBacking *backing) : SandboxAllocator(backing), watermark(backing->getBase()) {}
    Slot allocate(size_t request) throw std::bad_alloc;
};

class Sandbox {
public:
    virtual ~Sandbox() {}
    virtual Slot allocate(size_t request) throw std::bad_alloc = 0;
    virtual void finalize() = 0;
};

template <typename Backing, typename Allocator>
class SandboxImpl : public Sandbox {
private:
    Backing backing;
    Allocator alloc;
public:
    Sandbox(const Backing &&backing) : backing(backing), alloc(Allocator(backing)) {}

    virtual Slot allocate(size_t request) throw std::bad_alloc
        { return alloc.allocate(request); }
    virtual void finalize() { backing.finalize(); }
};

#endif
