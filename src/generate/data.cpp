#include "data.h"
#include "log/log.h"

ElfDataImpl::ElfDataImpl(Program *program, SandboxBacking *backing)
    : program(program), backing(backing) {

    opTrace = new ElfOperationTrace();

    pltIndexMap = new PLTIndexMap();
}

ElfDataImpl::~ElfDataImpl() {
    delete opTrace;
}

void ElfOperationTrace::add(const std::string &name) {
    executedCount[name] ++;
    traceOrder.push_back(name);
    LOG(9, "    executing operation [" << name << "]");
}

bool ElfOperationTrace::ran(const std::string &name) {
    return executedCount.find(name) != executedCount.end();
}

void ElfPipeline::add(UnnamedElfOperation *op) {
    op->setData(getData());
    op->setConfig(getConfig());
    pipeline.push_back(op);
}

void ElfPipeline::execute() {
    getData()->getOperationTrace()->add("[PIPELINE BEGIN]");
    checkDependencies();
    for(auto op : pipeline) {
        getData()->getOperationTrace()->add(op->getName());
        op->execute();
    }
    getData()->getOperationTrace()->add("[PIPELINE END]");
}

void ElfPipeline::checkDependencies() {
    for(auto dep : dependencyList) {
        if(!getData()->getOperationTrace()->ran(dep)) {
            LOG(1, "WARNING: dependency [" << dep
                << "] for pipeline [" << getName() << "] not yet executed");
        }
    }
}

