#include "data.h"
#include "log/log.h"

ElfDataImpl::ElfDataImpl(Program *program, BackingType *backing)
    : program(program), backing(backing) {

    opTrace = new ElfOperationTrace();
}

ElfDataImpl::~ElfDataImpl() {
    delete opTrace;
}

void ElfOperationTrace::add(const std::string &name) {
    executedCount[name] ++;
    traceOrder.push_back(name);
    LOG(9, "    executing operation [" << name << "]");
}

void ElfPipeline::add(ElfOperation *op) {
    op.setData(getData());
    op.setConfig(getConfig());
    pipeline.push_back(op);
}

void ElfPipeline::execute() {
    getData()->getOperationTrace()->add("[PIPELINE BEGIN]");
    checkDependencies();
    for(auto op : pipline) {
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

