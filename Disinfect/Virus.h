#ifndef VIRUS_H
#define VIRUS_H

#include <string>
#include <stdio.h>
#include "types.h"

using namespace std;

typedef enum {
    COMPANION,
    PREPENDER,
    FILE_INFECTOR
} VirusType;

const string VirusTypeNames[] = 
    { "Companion", "Prepender", "File Infector" };

class Virus
{
    public:
        Virus();
        Virus(std::string name, VirusType type, ULONG entryPoint, UINT size
                ,string signature);
        ~Virus();

        //getters and setters;
        std::string getName();
        void setName(std::string name);

        VirusType getType();
        void setType(VirusType virusType);

        UINT getSize();
        void setSize(UINT size);

        ULONG getEntryPoint();
        void setEntryPoint(UINT entryPoint);

        std::string toString();

    private:
        std::string m_Signature;
        //address of entry point if known (applies to file infector)
        ULONG m_EntryPoint;
        //size of the virus if known (applies prepender)
        UINT m_Size;
        std::string m_Name;
        VirusType m_Type;
};

#endif