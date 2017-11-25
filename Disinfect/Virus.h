#ifndef VIRUS_H
#define VIRUS_H

#include <string>
#include "types.h"

typedef enum {
    COMPANION,
    PREPENDER,
    FILE_INFECTOR
} VirusType;

class Virus
{
    public:
        Virus();
        Virus(std::string name, VirusType type, ULONG entryPoint, UINT size);
        ~Virus();

        //getters and setters;
        std::string getName();
        void setName(std::string name);

        VirusType getType();
        void setType(VirusType virusType);

        UINT getSize();
        void setSize(UINT size);

        ULONG entryPoint();
        void setSizE(UINT entryPoint);

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