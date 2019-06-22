#include <signal.h>
#include "chunk/tls.h"
#include "chunk/gstable.h"
#include "cminus/print.h"

// this is tailored for nginx JIT-shuffling. For other applications, the
// address registered with the kernel may need to be updated everytime
// the address of egalito_signal_handler changes in the sandbox.

using handlerType = void(*)(int, siginfo_t *, void *);

extern "C"
void egalito_signal_handler(int signum, siginfo_t *info, void *ucontext) {
    auto egalito_gsTable = EgalitoTLS::getGSTable();
    auto table = egalito_gsTable->getSignalTableAddress();
    auto handler = *(reinterpret_cast<handlerType *>(table) + signum);
    //egalito_printf("forwarding signal %d to %lx\n", signum, (long unsigned int)handler);
    handler(signum, info, ucontext);
}

extern "C"
int egalito_sigaction(int signum, struct sigaction *act,
    struct sigaction *oldact) {

    auto egalito_gsTable = EgalitoTLS::getGSTable();
    auto table = egalito_gsTable->getSignalTableAddress();

    auto buffer = reinterpret_cast<address_t *>(egalito_gsTable->getTableAddress());

    void *handler = nullptr;
    if(act->sa_flags & SA_SIGINFO) {
        handler = (void *)act->sa_sigaction;
        act->sa_sigaction = (handlerType)buffer[3];
    }
    else {
        handler = (void *)act->sa_handler;
        act->sa_handler = (void (*)(int))buffer[3];
    }
    *(reinterpret_cast<handlerType *>(table) + signum) = (handlerType)handler;

    //egalito_printf("egalito_sigaction %d will call %lx\n", signum, (long unsigned int)buffer[3]);

    return sigaction(signum, (const struct sigaction *)act, oldact);
}

