#include <signal.h>
#include <cstdio>
#include <cstdlib>
#include "signals.h"

static void sigsegv_handler(int sig, siginfo_t *info, void *context);

void Signals::registerHandlers() {
    {
        struct sigaction act = {};
        act.sa_sigaction = sigsegv_handler;
        sigemptyset(&act.sa_mask);
        act.sa_flags = SA_SIGINFO /*| SA_ONSTACK*/;

        sigaction(SIGSEGV, &act, nullptr);
    }
}

void sigsegv_handler(int sig, siginfo_t *info, void *context) {
    ucontext_t *uc = (ucontext_t *)context;
    unsigned long rip = uc->uc_mcontext.gregs[REG_RIP];
    std::printf("received SIGSEGV at 0x%lx\n", rip);
    std::exit(1);
}
