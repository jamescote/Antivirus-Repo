
#ifndef DISINFECTOR_H
#define DISINFECTOR_H

//will eventually need to open files
#include <fstream>
#include <string>
#include <iostream>

using namespace std;

#include "Virus.h"
#include "types.h"

class Disinfector
{
    public:
        Disinfector();
        ~Disinfector();

        //Might need to initialize
        void initialize();

        //should call WuManber
        Virus* detectVirus( std::string sFileName );

        void disinfect( Virus* virus );

    private:
        // Possible method stubs
        // Nothing here yet...


};

#endif