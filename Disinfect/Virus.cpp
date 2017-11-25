#include "Virus.h"
#include <iostream>

/* Public methods */
Virus::Virus()
{

}

Virus::Virus(std::string name, VirusType type, ULONG entryPoint, 
        UINT size, std::string signature)
{
    m_Name = name;
    m_Type = type;
    m_EntryPoint = entryPoint;
    m_Size = size;
    m_Signature.assign(signature);
}


string Virus::toString()
{
    char buf[16];
    sprintf(buf, "%08llx", m_EntryPoint);
    string entry = buf;

    string my_str = "Name: \t\t" + m_Name + "\n";
    my_str += "Type: \t\t" + VirusTypeNames[m_Type] + "\n";
    my_str += "Entry point: \t0x" + entry + "\n";
    my_str += "Size: \t\t" + std::to_string(m_Size) + "\n";
    my_str += "Signature: \t" + m_Signature + "\n";
    my_str += "\n";

    cout << my_str;

    return my_str;
}

//getters and setters;

// getter/setter for name
std::string Virus::getName(){ return m_Name; }
void Virus::setName(std::string name)
{
    if(!name.empty())
        m_Name.assign(name);
}

// getter/setter for type
VirusType Virus::getType() { return m_Type; }
void Virus::setType(VirusType virusType)
{
    m_Type = virusType;
}

// getter/setter for size
UINT Virus::getSize() { return m_Size; }
void Virus::setSize(UINT size)
{
    if (size > 0)
        m_Size = size;
}

// getter/setter for entry point
ULONG Virus::getEntryPoint() { return m_EntryPoint; }
void Virus::setEntryPoint(UINT entryPoint)
{
    if (entryPoint > 0)
        m_EntryPoint = entryPoint;
}

/*
    Destructor - handle cleanup
*/
Virus::~Virus()
{
    
}
