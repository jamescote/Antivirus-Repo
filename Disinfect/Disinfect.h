
#ifndef DISINFECTOR_H
#define DISINFECTOR_H

#include <string>
#include <iostream>
#include <fstream>
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
        Virus* detectType( std::string sFileName );

        void disinfect( Virus* virus );

    private:
        // Possible method stubs
        // Nothing here yet...
        

};

#endif