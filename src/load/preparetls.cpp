#include "preparetls.h"
#include "../dep/rtld/tcbhead.h"
#include "conductor/conductor.h"
#include "log/log.h"

#ifdef ARCH_X86_64
extern "C" void _set_fs(address_t fs);
#elif defined(ARCH_AARCH64)
extern "C" void _set_tpidr_el0(address_t addr);
#endif

void PrepareTLS::prepare(Conductor *conductor) {
#ifdef ARCH_X86_64
    auto main_tp = conductor->getMainThreadPointer();

    void *_thrdescr = reinterpret_cast<void *>(main_tp);
    struct my_tcbhead_t *_head = static_cast<struct my_tcbhead_t *>(_thrdescr);

    // as per libc/sysdeps/x86_64/nptl/tls.h
    _head->tcb = _thrdescr;
    _head->self = _thrdescr;

    // this should be at %fs:0x28
    uint64_t canary;
    __asm__ __volatile__ (
        "mov %@:%p1, %0"
            : "=r"(canary)
            : "i"(offsetof(my_tcbhead_t, stack_guard))
    );
    LOG(1, "copying stack canary: 0x" << std::hex << canary);
    _head->stack_guard = canary;

    // this should be at %fs:0x30
    uint64_t pointer_guard;
    __asm__ __volatile__ (
        "mov %@:%p1, %0"
            : "=r"(pointer_guard)
            : "i"(offsetof(my_tcbhead_t, pointer_guard))
    );
    _head->pointer_guard = pointer_guard;

#if 0
    uint32_t multiple_threads;
    __asm__ __volatile__ (
        "mov %@:%p1, %0"
            : "=r"(multiple_threads)
            : "i"(offsetof(my_tcbhead_t, multiple_threads))
    );
    LOG(1, "copying multiple_threads: 0x" << std::hex << multiple_threads);
    _head->multiple_threads = multiple_threads;
#endif

    LOG(1, "set %""fs to point at " << main_tp);
    _set_fs(main_tp);
#elif defined(ARCH_AARCH64)
    auto main_tp = conductor->getMainThreadPointer();
    _set_tpidr_el0(main_tp);
#endif
}
