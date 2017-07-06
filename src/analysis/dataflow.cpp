#include "analysis/dataflow.h"
#include "analysis/walker.h"
#include "analysis/usedef.h"
#include "chunk/concrete.h"
#include "instr/semantic.h"
#include "instr/linked-aarch64.h"
#include "operation/find2.h"

#include "log/log.h"

void DataFlow::addUseDefFor(Function *function) {
    auto graph = new ControlFlowGraph(function);
    auto config = new UDConfiguration(graph);
    auto working = new UDRegMemWorkingSet(function, graph);
    auto usedef = new UseDef(config, working);

    SccOrder order(graph);
    order.genFull(0);
    usedef->analyze(order.get());

    flowList[function] = usedef;
    workingList.push_back(working);
    configList.push_back(config);
    graphList.push_back(graph);
}

UDRegMemWorkingSet *DataFlow::getWorkingSet(Function *function) {
    auto it = flowList.find(function);
    if(it == flowList.end()) {
        addUseDefFor(function);
    }
    return flowList[function]->getWorkingSet<UDRegMemWorkingSet>();
}

void DataFlow::adjustCallUse(
    LiveRegister *live, Function *function, Module *module) {

    for(auto block : CIter::children(function)) {
        for(auto instr: CIter::children(block)) {
            auto s = instr->getSemantic();
            auto assembly = s->getAssembly();
            if(!assembly) continue;
            if(assembly->getId() != ARM64_INS_BL) continue;

            auto v = dynamic_cast<ControlFlowInstruction *>(s);
            Function *func = nullptr;
            if(auto target = v->getLink()->getTarget()) {
                func = ChunkFind2().findFunctionInModule(
                    target->getName().c_str(), module);
            }
            if(!func) continue;

            auto working = getWorkingSet(function);
            auto state = working->getState(instr);

            auto info = live->getInfo(func);
            LOG0(9, "live registers for " << func->getName());
            for(size_t i = 0; i < 32; i++) {
                if(info.get(i)) {
                    LOG0(9, " " << i);
                }
            }
            LOG(9, "");

            //R0 - R18
            auto ud = flowList[function];
            for(int i = 0; i < 19; i++) {
                if(info.get(i)) {
                    LOG(5, "canceling use of " << std::dec << i);
                    ud->cancelUseDefReg(state, i);
                }
            }
            IF_LOG(5) state->dumpState();
        }
    }
}

DataFlow::~DataFlow() {
    for(auto m : flowList) {
        delete m.second;
    }
    for(auto s : workingList) {
        delete s;
    }
    for(auto c : configList) {
        delete c;
    }
    for(auto g : graphList) {
        delete g;
    }
}
