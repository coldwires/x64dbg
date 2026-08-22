#include "exceptiondirectoryanalysis.h"
#include "module.h"
#include "TitanEngine/TitanEngine.h"
#include "memory.h"
#include "console.h"
#include "function.h"

#include <unordered_map>

ExceptionDirectoryAnalysis::ExceptionDirectoryAnalysis(duint base, duint size)
    : Analysis(base, size)
{
#ifdef _WIN64
    SHARED_ACQUIRE(LockModules);

    auto modInfo = ModInfoFromAddr(base);
    if(modInfo == nullptr)
        return;

    mModuleBase = modInfo->base;
    mRuntimeFunctions = modInfo->runtimeFunctions;
    mParentFunctions = modInfo->parentFunctions;
#endif // _WIN64
}

void ExceptionDirectoryAnalysis::Analyse()
{
#ifdef _WIN64
    //A function is often described by several entries, the later ones carrying
    //UNW_FLAG_CHAININFO and pointing back at the first. Resolve each entry to the
    //function it belongs to so that the fragments can be joined.
    std::unordered_map<uint32_t, uint32_t> parents;
    for(const auto & parent : mParentFunctions)
        parents[parent.first] = parent.second;

    auto rootOf = [&parents](uint32_t rva)
    {
        //Bounded so a malformed chain cannot spin here.
        for(size_t i = 0; i < parents.size() + 1; i++)
        {
            auto found = parents.find(rva);
            if(found == parents.end())
                break;
            rva = found->second;
        }
        return rva;
    };

    //mRuntimeFunctions is sorted by (begin, end), so fragments of one function appear
    //in address order and a contiguous run can be joined as it is walked.
    for(size_t i = 0; i < mRuntimeFunctions.size(); i++)
    {
        auto begin = mRuntimeFunctions[i].BeginAddress;
        auto end = mRuntimeFunctions[i].EndAddress;
        auto root = rootOf(begin);

        //Only join fragments that touch. A function split into distant pieces stays
        //split, because one interval covering the gap would claim everything between.
        while(i + 1 < mRuntimeFunctions.size()
                && mRuntimeFunctions[i + 1].BeginAddress == end
                && rootOf(mRuntimeFunctions[i + 1].BeginAddress) == root)
        {
            end = mRuntimeFunctions[i + 1].EndAddress;
            i++;
        }

        auto funcAddr = mModuleBase + begin;
        auto funcEnd = mModuleBase + end - 1;

        // If within limits...
        if(inRange(funcAddr) && inRange(funcEnd) && funcAddr <= funcEnd)
            mFunctions.push_back({ funcAddr, funcEnd });
    }
    dprintf(QT_TRANSLATE_NOOP("DBG", "%u functions discovered!\n"), DWORD(mFunctions.size()));
#else //x32
    dputs(QT_TRANSLATE_NOOP("DBG", "This kind of analysis doesn't work on x32 executables...\n"));
#endif // _WIN64
}

void ExceptionDirectoryAnalysis::SetMarkers()
{
    FunctionDelRange(mBase, mBase + mSize - 1, false);
    for(const auto & function : mFunctions)
        FunctionAdd(function.first, function.second, false);
}
