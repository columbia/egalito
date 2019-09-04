#include <iostream>
#include <typeinfo>
#include <cctype>
#include "passes.h"
#include "pass/chunkpass.h"
#include "util/timing.h"

#undef DEBUG_GROUP
#define DEBUG_GROUP shell
#define D_shell 9
#include "log/log.h"


#include "pass/cancelpush.h"
#include "pass/chunkpass.h"
#include "pass/clearplts.h"
#include "pass/clearspatial.h"
#include "pass/collapseplt.h"
#include "pass/collectglobals.h"
#include "pass/debloat.h"
#include "pass/detectnullptr.h"
#include "pass/dumplink.h"
#include "pass/dumptlsinstr.h"
#include "pass/encodingcheckpass.h"
#include "pass/endbradd.h"
#include "pass/endbrenforce.h"
#include "pass/externalcalls.h"
#include "pass/externalsymbollinks.h"
#include "pass/fallthrough.h"
#include "pass/findendbr.h"
#include "pass/findinitfuncs.h"
#include "pass/findsyscalls.h"
#include "pass/fixdataregions.h"
#include "pass/fixenviron.h"
#include "pass/fixjumptables.h"
#include "pass/handlecopyrelocs.h"
#include "pass/handledatarelocs.h"
#include "pass/handlerelocs.h"
#include "pass/hijack.h"
#include "pass/ifunclazy.h"
#include "pass/ifuncplts.h"
#include "pass/inferlinks.h"
#include "pass/injectbridge.h"
#include "pass/instrumentcalls.h"
#include "pass/instrumentinstr.h"
#include "pass/internalcalls.h"
#include "pass/jitgsfixup.h"
#include "pass/jitgssetup.h"
#include "pass/jtoverestimate.h"
#include "pass/jumptablebounds.h"
#include "pass/jumptablepass.h"
#include "pass/ldsorefs.h"
#include "pass/logcalls.h"
#include "pass/loginstr.h"
#include "pass/makecache.h"
#include "pass/nonreturn.h"
#include "pass/noppass.h"
#include "pass/permutedata.h"
#include "pass/populateplt.h"
#include "pass/positiondump.h"
#include "pass/promotejumps.h"
#include "pass/regreplace.h"
#include "pass/relocheck.h"
#include "pass/removepadding.h"
#include "pass/reorderpush.h"
#include "pass/resolveexternallinks.h"
#include "pass/resolveplt.h"
#include "pass/resolvetls.h"
#include "pass/retpoline.h"
#include "pass/run.h"
#include "pass/shadowstack.h"
#include "pass/splitbasicblock.h"
#include "pass/splitfunction.h"
#include "pass/stackextend.h"
#include "pass/stackxor.h"
#include "pass/switchcontext.h"
#include "pass/syscallsandbox.h"
#include "pass/updatelink.h"
#include "pass/usegstable.h"

PassContext::PassContext(std::vector<EgalitoChunkType> types,
    GeneratorType generator) : handled{}, generator(generator) {

    for(auto type : types) {
        handled[type] = true;
    }
}

PassContext::PassContext(bool defaultValue, std::vector<EgalitoChunkType> types,
    GeneratorType generator) : generator(generator) {

    for(size_t i = 0; i < sizeof(handled)/sizeof(*handled); i ++) {
        handled[i] = defaultValue;
    }
    for(auto type : types) {
        handled[type] = !defaultValue;
    }
}

bool PassContext::isSupported(Chunk *chunk) const {
    return handled[chunk->getFlatType()];
}

ChunkPass *PassContext::create(Chunk *chunk) const {
    return generator(chunk);
}

void PassCommands::makePassMap(EgalitoInterface *egalito) {
    passMap["cancelpush"] = PassContext({TYPE_Program, TYPE_Module},
        [egalito] (Chunk *chunk)
            { return new CancelPushPass(egalito->getProgram()); });
    passMap["collapseplt"] = PassContext(true, {},
        [egalito] (Chunk *chunk)
            { return new CollapsePLTPass(egalito->getConductor()); });
    passMap["endbradd"] = PassContext(true, {},
        [] (Chunk *chunk) { return new EndbrAddPass(); });
    passMap["endbrenforce"] = PassContext(true, {},
        [] (Chunk *chunk) { return new EndbrEnforcePass(); });
    passMap["stackxor"] = PassContext({TYPE_Program},
        [] (Chunk *chunk) { return new StackXOR(0x28); });
    passMap["shadowstackconst"] = PassContext(true, {},
        [] (Chunk *chunk) { return new ShadowStackPass(ShadowStackPass::MODE_CONST); });
    passMap["shadowstackgs"] = PassContext(true, {},
        [] (Chunk *chunk) { return new ShadowStackPass(ShadowStackPass::MODE_GS); });

#if 0
pass/clearplts.h
pass/clearspatial.h
pass/collapseplt.h
pass/collectglobals.h
pass/debloat.h
pass/detectnullptr.h
pass/dumplink.h
pass/dumptlsinstr.h
pass/encodingcheckpass.h
pass/externalcalls.h
pass/externalsymbollinks.h
pass/fallthrough.h
pass/findendbr.h
pass/findinitfuncs.h
pass/findsyscalls.h
pass/fixdataregions.h
pass/fixenviron.h
pass/fixjumptables.h
pass/handlecopyrelocs.h
pass/handledatarelocs.h
pass/handlerelocs.h
pass/hijack.h
pass/ifunclazy.h
pass/ifuncplts.h
pass/inferlinks.h
pass/injectbridge.h
pass/instrumentcalls.h
pass/instrumentinstr.h
pass/internalcalls.h
pass/jitgsfixup.h
pass/jitgssetup.h
pass/jtoverestimate.h
pass/jumptablebounds.h
pass/jumptablepass.h
pass/ldsorefs.h
pass/logcalls.h
pass/loginstr.h
pass/makecache.h
pass/nonreturn.h
pass/noppass.h
pass/permutedata.h
pass/populateplt.h
pass/positiondump.h
pass/promotejumps.h
pass/regreplace.h
pass/relocheck.h
pass/removepadding.h
pass/reorderpush.h
pass/resolveexternallinks.h
pass/resolveplt.h
pass/resolvetls.h
pass/retpoline.h
pass/run.h
pass/shadowstack.h
pass/splitbasicblock.h
pass/splitfunction.h
pass/stackextend.h
pass/stackxor.h
pass/switchcontext.h
pass/syscallsandbox.h
pass/updatelink.h
pass/usegstable.h
#endif
}

bool PassCommands::runPassCommand(EgalitoInterface *egalito, ShellState &state,
    ArgumentValueList &args) const {

    Chunk *chunk = nullptr;
    if(args.getIndexedCount() > 1) {
        chunk = args.getIndexed(1).getChunk(egalito);
    }
    else chunk = state.getChunk();
    if(!chunk) return false;

    auto passName = args.getIndexed(0).getString();
    std::string passNameLower = passName;
    std::transform(passName.begin(), passName.end(),
        passNameLower.begin(), ::tolower);
    auto it = passMap.find(passNameLower);
    if(it == passMap.end()) {
        LOG(0, "unknown pass name \"" << passName << "\"");
        return false;
    }
    auto &context = (*it).second;

    if(args.getBool("-f", false) || context.isSupported(chunk)) {
        auto pass = context.create(chunk);

        if(args.getBool("-t", false)) {
            // an expansion of RUN_PASS
            EgalitoTiming timing(passName.c_str());
            chunk->accept(pass);
        }
        else {
            chunk->accept(pass);
        }

        delete pass;
    }
    else {
        LOG(0, "ERROR: unsupported chunk type " << typeid(*chunk).name()
            << " for pass " << passName << ", use -f to run anyway");
        return false;
    }

    return true;
}

bool PassCommands::listPassesCommand(ShellState &state, ArgumentValueList &args) const {
    std::string search;
    if(args.getIndexedCount() > 0) {
        search = args.getIndexed(0).getString();
    }
    std::string searchLower;
    std::transform(search.begin(), search.end(),
        searchLower.begin(), ::tolower);

    for(auto kv : passMap) {
        auto name = kv.first;
        auto &pass = kv.second;
        if(!search.length() || name.find(search) != std::string::npos) {
            LOG(0, name);

            if(args.getBool("-l")) {
                LOG0(0, "    works on:");
                for(int i = TYPE_UNKNOWN; i < TYPE_TOTAL; i ++) {
                    auto type = static_cast<EgalitoChunkType>(i);
                    if(pass.isSupported(type)) {
                        LOG0(0, " " << getChunkTypeName(type));
                    }
                }
                LOG(0, "");  // newline
            }
        }
    }
    return true;
}

void PassCommands::construct(EgalitoInterface *egalito) {
    makePassMap(egalito);

    fullList->add(new FunctionCommand("lspass",
        ArgumentSpecList(
            {
                {"-l", ArgumentSpec({"-l"}, ArgumentSpec::TYPE_FLAG)}
            }, {
                ArgumentSpec(ArgumentSpec::TYPE_PASS)
            }),
        std::bind(&PassCommands::listPassesCommand, this,
            std::placeholders::_1, std::placeholders::_2),
        "shows all passes matching a given substring"));
    fullList->add(new FunctionCommand("pass",
        ArgumentSpecList(
            {
                {"-f", ArgumentSpec({"-f"}, ArgumentSpec::TYPE_FLAG)},
                {"-t", ArgumentSpec({"-t"}, ArgumentSpec::TYPE_FLAG)},
            }, {
                ArgumentSpec(ArgumentSpec::TYPE_PASS),
                ArgumentSpec(ArgumentSpec::TYPE_STRING)
            }, 1),
        std::bind(&PassCommands::runPassCommand, this,
            egalito, std::placeholders::_1, std::placeholders::_2),
        "runs an arbitrary pass at the current Chunk location"));
}

std::vector<std::string> PassCommands::getNames() const {
    std::vector<std::string> names;
    for(auto kv : passMap) {
        names.push_back(kv.first); 
    }
    return std::move(names);
}
