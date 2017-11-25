#!/usr/bin/python2.7
""" imports for dictionary updater """
import sys
import argparse
import re
import traceback
import os

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
                        type=row_format, nargs='*', action="append")
    
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

def get_virus_index(lines, virus_name):
    index = 0
    
    for line in lines:
        if line.startswith("v {}".format(virus_name)):
            break
        index+=1

    return index


def delete_virus(database, virus_name):
    """ delete an entire virus entry from the database """

    contents = None

    try:
        with open(database, "r+") as db_file:
            contents = db_file.readlines()
            virus_index = get_virus_index(contents, virus_name)
                
            if virus_index != 0 and virus_index < len(contents):
                next_index = virus_index + 1
                while next_index < len(contents) and not contents[next_index].startswith("v "):
                    next_index+=1

                print('deleting lines {} to {}'.format(virus_index, next_index))
                del contents[virus_index:next_index]

        with open(database,"w") as db_file:
            db_file.write(''.join(contents))
    except:
        print("aww naww, something went wrong in delete_virus")
    
def update_virus_fields(database, virus_name, fields):
    """ update virus fields to have new value - does nothing if fields are not present """
    if not fields:
        return

    try:
        with open(database, "r+") as db_file:
            contents = db_file.readlines()
            #index of virus
            index = get_virus_index(contents, virus_name)

            if index != 0 and index < len(contents):
                existing_fields = get_fields(index+1, contents)
            
                for field in fields:
                    field_elements = field.split('=')
                    if field_elements[0] in existing_fields:
                        #update field
                        print("Updating field {} with data {}".format(field_elements[0], field_elements[1]))
                        contents[existing_fields[field_elements[0]]] = "{} {}\n".format(field_elements[0], field_elements[1])
                    else:
                        print("Virus {} does not have field '{}'.".format(virus_name, field_elements[0]))
                
                db_file.seek(0,0)
                db_file.write(''.join(contents))
    except:
        print("Something went wrong in update_virus_fields")
        traceback.print_exc(5)

    
def delete_virus_fields(database, virus_name, fields):
    """ delete fields from the virus definition - does nothing if fields are not present """
    if not fields:
        return

    contents = None

    try:
        with open(database, "r+") as db_file:
            contents = db_file.readlines()
            index = get_virus_index(contents, virus_name)

            if index != 0 and index < len(contents):
                existing_fields = get_fields(index+1, contents)
            
                for field in fields:
                    field_elements = field.split('=')
                    if field_elements[0] in existing_fields:
                        del contents[existing_fields[field_elements[0]]]
                    else:
                        print("Virus {} does not have field '{}'.".format(virus_name, field_elements[0]))

        if contents:
            with open(database, "w") as db_file:
                db_file.write(''.join(contents))
    except:
        print("Something went wrong in delete_virus_fields: ")
        traceback.print_exc()


def insert_virus_fields(database, virus_name, fields):
    """ insert new fields into the virus definition """
    if not fields:
        return

    try: 
        with open(database, "r+") as db_file:
            contents = db_file.readlines()
            #index of virus
            index = get_virus_index(contents, virus_name)

            if index != 0 and index < len(contents):
                existing_fields = get_fields(index+1, contents)
            
                for field in fields:
                    field_elements = field.split('=')
                    if field_elements[0] not in existing_fields:
                        contents.insert(index+1, "{} {}\n".format(field_elements[0], field_elements[1]))
                    else:
                        print("Virus {} already has field '{}'. Use update instead.".format(virus_name, field_elements[0]))
                
                db_file.seek(0,0)
                db_file.write(''.join(contents))
    except:
        print("Something went wrong in insert_virus_fields: {}".format(traceback.print_exc(5)))


def get_fields(index, contents):
    """ given the index in a list of lines of a virus, get_fields will return a dictionary of all fields found at this virus entry
    and the index at which they are found. This can be used to ensure that a given field exists to update, or a field does not exist when inserting
    """
    ex_fields = {}
    while index < len(contents) and not contents[index].startswith('v '):
        #add starting character of field until we see v, these are viruses current properties
        ex_fields[contents[index][0]] = index
        index+=1

    return ex_fields
        
                               
def get_file_size(file_path):
    """ gets the file size of an open descriptor """
    try:
        return os.path.getsize(file_path)
    except:
        return -1


def parse_args(args):
    """ parses the arguments and executes the specified commands """
    print("Running with arguments:")
    print("Action: {}".format(args.action))
    print("Database file: {}".format(args.database))
    print("Virus_name: {}".format(args.virus_name))
    
    if args.action[0] != 'D':
        print("Row commands: {}".format(args.fields))

    if args.action[0] == 'D':
        delete_virus(args.database[0], args.virus_name[0])
    elif args.action[0] == 'u':
        update_virus_fields(args.database[0], args.virus_name[0], args.fields[0])
    elif args.action[0] == 'i':
        insert_virus_fields(args.database[0], args.virus_name[0], args.fields[0])
    elif args.action[0] == 'd':
        delete_virus_fields(args.database[0], args.virus_name[0], args.fields[0])
        

def main():
    parse_args(gen_arg_parser())
    

if __name__ == "__main__":
    main()
