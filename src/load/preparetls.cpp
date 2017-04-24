#include "preparetls.h"
#include "dep/rtld/tcbhead.h"
#include "conductor/conductor.h"
#include "log/log.h"

#ifdef ARCH_X86_64
extern "C" void _set_fs(address_t fs);
#endif

void PrepareTLS::prepare(Conductor *conductor) {
#ifdef ARCH_X86_64
    auto main_tp = conductor->getMainThreadPointer();

    void *_thrdescr = reinterpret_cast<void *>(main_tp);
    struct my_tcbhead_t *_head = static_cast<struct my_tcbhead_t *>(_thrdescr);

    // as per libc/sysdeps/x86_64/nptl/tls.h
    _head->tcb = _thrdescr;
    _head->self = _thrdescr;

    LOG(1, "set %""fs to point at " << main_tp);
    _set_fs(main_tp);
#endif
}
