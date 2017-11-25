#!/usr/bin/python2.7
import sys
import traceback
import os
from hancock import Hancock, HancockError

#def eprint(*args, **kwargs):
#    print(*args, file=sys.stderr, **kwargs)

def dprint(msg, debug):
    if debug:
        print(msg)
    
def main():
    if len(sys.argv) < 7 or len(sys.argv) > 8:
        print("{}:Incorrect usage. Proper usage:".format(sys.argv[0]))
        print("python2.7 {} file1 file2 virus_name db_file min_signature max_signature [-d]".format(sys.argv[0]))
        exit(1)

    debug = False
    
    if len(sys.argv) == 8 and (sys.argv[7] == '-d'):
        debug = True

    in_file_path = sys.argv[1]
    comp_file_path = sys.argv[2]

    virus_name = sys.argv[3]
    db_file_path = sys.argv[4]

    try:
        min_size = int(sys.argv[5])
        max_size = int(sys.argv[6])

        if min_size >= max_size:
            raise ValueError("{}: min_size must be smaller than the max_size".format(sys.argv[0]))
        
        finder = Hancock(in_file_path, comp_file_path, debug)
        signature = finder.find_signature_linear(min_size, max_size)

        # try linear search first
        if not signature[1]:
            print("No signature found in linear search, trying substring search...")
            signature = finder.find_signature_substring(min_size, max_size)

            #if no signature, try substring search
            if not signature[1]:
                print("No Signature found between {} and {} ".format(in_file_path, comp_file_path))
                os._exit(1)
        
        print("Signature found, attempting to write to {}".format(db_file_path))
            
        with open(db_file_path, 'ab') as db_file:
            db_file.write('v {}\n'.format(virus_name))
            db_file.write('s {}\n'.format(signature[1]))
            db_file.write('o {}\n'.format(signature[0]))
            db_file.write('.\n')


    except IOError as ex:
        print("file not found: {}".format(str(ex)))
    except HancockError as ex:
        print("Error, ensure that you are using python2.7.")
        print(str(ex))
    except ValueError as ex:
        print(str(ex))
    except:
        if debug:
            print(traceback.print_exc(5))
        print("Error, ensure that you are using python2.7.")
    

if __name__ == "__main__":
    main()
