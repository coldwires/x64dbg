#ifndef _EXCEPTIONDIRECTORYANALYSIS_H
#define _EXCEPTIONDIRECTORYANALYSIS_H

#include "analysis.h"
#include <functional>

class ExceptionDirectoryAnalysis : public Analysis
{
public:
    ExceptionDirectoryAnalysis(duint base, duint size);
    void Analyse() override;
    void SetMarkers() override;

private:
    duint mModuleBase = 0;
    std::vector<std::pair<duint, duint>> mFunctions;

#ifdef _WIN64
    std::vector<RUNTIME_FUNCTION> mRuntimeFunctions;
    std::vector<std::pair<uint32_t, uint32_t>> mParentFunctions;
#endif // _WIN64
};

#endif //_EXCEPTIONDIRECTORYANALYSIS_H