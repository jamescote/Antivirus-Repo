import sys
import os
import traceback
from difflib import SequenceMatcher

class Hancock:
    def __init__(self, in_path, comp_path, debug):
        self.debug = debug
        
        if self.is_file(in_path) and self.is_file(comp_path):
            self._in_path = in_path
            self._comp_path = comp_path
        else:
            raise HancockError("Errors in supplied parameters.")

    def find_signature_substring(self, min_size, max_size):
        """ 
        fallback to handle when a signature is not found using the linear pass

        Tries to find a suitably sized substring that is present in both files
        
        """

        signature = (0, bytearray())
        match = None
        
        try:
            with open(sys.argv[1], 'rb') as f1, open(sys.argv[2], 'rb') as f2:
                f1_text = f1.read().encode('hex')
                f2_text = f2.read().encode('hex')
                
                matcher = SequenceMatcher(None, f1_text, f2_text, autojunk=False)
                match = matcher.find_longest_match(0, len(f1_text), 0, len(f2_text))

                offset = -1

                print(f1_text[match.a:match.a + match.size])

                #if match is of acceptable size
                if match.size >= min_size:
                    #if we found the substring in the same location, we have offset
                    if match.a == match.b:
                        offset = match.a

                    substr = f1_text[match.a:match.a + match.size]

                    #cut off leading zeroes by finding first index where i,i+1 is not 00
                    i = 0
                    while substr[i] + substr[i+1] == '00':
                        i+=2

                    substr = substr[i:]

                    #if substring is larger than max size, truncate to max_size
                    if len(substr) > max_size:
                        substr = substr[0:max_size]
                        
                    signature = (offset, substr)
                        
        except:
            dprint(traceback.print_exc(5))

        return signature


            


    def find_signature_linear(self, min_size, max_size):
        """ 
        Does a linear byte for byte pass of both files to determine a signature 
        
        Naive in such that it will fail to find a signature on polymorphic code
        or file infectors - but runs in n time.
        """
        signature = bytearray()
        in_byte = None
        comp_byte = None

        #number of bytes we have matched thus far
        bytes_matched = 0
        
        #tuple indicating index of signature and signature
        ret_signature = (0, bytearray())

        #variable used to track acceptable number of zeroes in signature - initialized to avoid
        #reference before instantiation errors.
        num_zeroes = 0
        
        try:
            index = 0
            search_space = min(self.get_size(self._in_path), self.get_size(self._comp_path))
            
            with open(self._in_path, "rb") as in_file, open(self._comp_path, "rb") as comp_file:
                while index < search_space:
                    #read in a byte at at ime
                    in_byte = in_file.read(1).encode('hex')
                    comp_byte = comp_file.read(1).encode('hex')

                    #print("{} {}".format(in_byte, comp_byte))
                    #if both bytes are 0s, dont match unless there are only a few - fast track the files past the zeros
                    if in_byte == "00" and comp_byte == "00" and len(signature) == 0:
                        # dont start the signature with 0
                        pass
                    elif num_zeroes <= 0 and in_byte == "00" and comp_byte == "00":
                        (index, num_zeroes) = self.fast_track(in_file, comp_file, index, search_space, 8)
                        # found an unacceptible number of zeroes in a row, start pattern over
                        if num_zeroes == 0:
                            bytes_matched = 0
                            signature = ""
                    # if they match, increment match counter and add byte to signature
                    elif in_byte == comp_byte:
                        if in_byte == '00' and comp_byte == '00':
                            # if we saw zeroes earlier and the fast_track determined the zeroes were okay to add, 
                            num_zeroes -= 1
                            
                        bytes_matched += 1                    
                        signature += in_byte

                        #if we've reached the max required size, break, return signature
                        
                        if bytes_matched > min_size and bytes_matched > len(ret_signature[1]):
                            # add 1 because we haven't incremented index yet
                            ret_signature = (index - bytes_matched + 1, signature)
                            
                        if bytes_matched >= max_size:
                            break

                    else:
                        bytes_matched = 0
                        signature = bytearray()
                        
                    index += 1

                    
        except:
            self.dprint(traceback.print_exc(5))
            raise HancockError("Error opening files")

        return ret_signature


    def fast_track(self, in_file, comp_file, index, search_space, acceptable_count):
        """ takes in two files and that are assumed to have read a 0 at the same spot,
        it then checks to see how many subsequent zeroes follow. If it is more than acceptable_count,
        seek into the files till we find non-zero"""
        #maintain the previous index unless we 
        start_index = index

        #dont reuse parameter variables
        cur_index = index
        zero_count = 0

        in_byte = "00"
        comp_byte = "00"

        while cur_index < search_space and (in_byte == "00" and comp_byte == "00"):
            #initial increment will always happen - caller already saw a zero, that's why we're in here
            zero_count += 1 
            in_byte = in_file.read(1).encode('hex')
            comp_byte = in_file.read(1).encode('hex')
            cur_index += 1
            

        if zero_count < acceptable_count:
            #seek back to where first zero was read
            in_file.seek(start_index, 0)
            comp_file.seek(start_index, 0)
            #return original index of first zero and the number of subsequent zeroes that will be found
            return(start_index - 1, zero_count)
        else:
            #else fix file pointers to cur_index - 1, to where we saw last acceptable byte
            #tell caller where new index is, and that there are 0 subsequent zeroes to be found
            #(we skipped over them)
            in_file.seek(cur_index - 1, 0)
            comp_file.seek(cur_index - 1, 0)
            return(cur_index - 1, 0)        
        

    def is_file(self, file_path):
        b_is_file = False
        
        try:
            if os.path.isfile(file_path):
                b_is_file = True
        except FileNotFoundError as ex:
            print("File not found.")
            self.dprint(traceback.print_exc(5))

        return b_is_file

    def get_size(self, file_path):
        file_size = -1
        try:
            file_stat = os.stat(file_path)
            if file_stat:
                file_size = file_stat.st_size

        except IOError as ex:
            print("File not found.")
            self.dprint(traceback.print_exc(5))
                
        return file_size

    #def eprint(self, *args, **kwargs):
    #    print(*args, file=sys.stderr, **kwargs)
        
    def dprint(self, msg):
        if self.debug:
            print(msg)


class HancockError(Exception):
    def __init__(self, msg):
        self._msg = "HancockError: {}".format(msg)

    def __str__(self):
        return str(self._msg)
