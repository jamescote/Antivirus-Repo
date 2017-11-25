#!/usr/bin/python2.7
""" imports for dictionary updater """
import sys
import argparse
import re

def row_format(s, pat=re.compile(r'[a-zA-Z]=[a-zA-Z0-9]*')):
    """ custom type for row format in arguments """
    if not pat.match(s):
        raise argparse.ArgumentTypeError('row format is c=outputforrow. c may only be one character, lower or upper case.')
    return s


def gen_arg_parser():
    """ """
    parser = argparse.ArgumentParser(description='dictionary updater')
    parser.add_argument('action', help="u=update row, d=delete row, i=insert row, D=delete whole virus",
                        type=str, nargs=1, choices=['u','d','i','D'])
    
    parser.add_argument('database', help="file where virus data is located",
                        type=str, nargs=1)
    
    parser.add_argument('virus_name', help="the name of the virus entry to modify (assumed to be unique)",
                        type=str, nargs=1 )
    
    parser.add_argument('fields', help="a list of fields to update/delete/insert. Format is c=Value. For option d simply use c= with no value specified",
                        type=row_format, nargs='?', action="append")
    
    args = parser.parse_args()

    if args.action[0] != 'D':
        if not args.fields[0]:
            print("error: argument fields must be present with action option '{}'.".format(args.action[0]))
            exit(1)
    else:
        if args.fields[0]:
            print("error: argument fields were supplied with action option '{}'. Did you mean 'd'?".format(args.action[0]))
            exit(1)

    return args

def delete_virus(database, virus_name):
    """ delete an entire virus entry from the database """

def update_virus_fields(database, virus_name, fields):
    """ update virus fields to have new value - does nothing if fields are not present """

def delete_virus_fields(database, virus_name, fields):
    """ delete fields from the virus definition - does nothing if fields are not present """

def insert_virus_fields(database, virus_name, fields):
    """ insert new fields into the virus definition """ 

def parse_args(args):
    """ parses the arguments and executes the specified commands """
    print("Running with arguments:")
    print("Action: {}".format(args.action))
    print("Database file: {}".format(args.database))
    print("Virus_name: {}".format(args.virus_name))
    
    if args.action[0] != 'D':
        print("Row commands: {}".format(args.fields))

    if args.action[0] == 'D':
        delete_virus(args.database, args.virus_name)
    elif args.action[0] == 'u':
        update_virus_fields(args.database, args.virus_name, args.fields)
    elif args.action[0] == 'i':
        insert_virus_fields(args.database, args.virus_name, args.fields)
    elif args.action[0] == 'd':
        delete_virus_fields(args.database, args.virus_name, args.fields)
        

    #if(action=)

def main():
    """
    main driver for dictionary updater
    expects arguments in the following fashion:
    [VirusName]
    [update/delete/insert/DELETEVIRUS]
    [ ch=[field]
    For each pair encountered, it will seperate
    """
    parse_args(gen_arg_parser())

    





if __name__ == "__main__":
    main()
