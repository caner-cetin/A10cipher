import os
import numpy as np
import sys
import os
import argparse
from cryptography.fernet import Fernet
from pathlib import Path
def write_key():
    #Generate a key and store it
    key = Fernet.generate_key()
    with open("encryption_key.txt", "wb") as file:
        file.write(key)
    return key
def load_key():
    return open("encryption_key.txt","rb").read()
def convert_txt_to_morse_AAAA(message,filename):
    #Short ping is A and long ping is AAA, so letter "A" is equal to .- and A AAA
    AAAAA_code_DICT_upper ={
                    'A':'A AAA', 'B':'AAA A A A ',
                    'C':' AAA A AAA A', 'D':' AAA A A', 'E':' A',
                    'F':' A A AAA A', 'G':' AAA AAA A', 'H':' A A A A',
                    'I':' A A', 'J':' A AAA AAA AAA', 'K':' AAA A AAA',
                    'L':' A AAA A A', 'M':' AAA AAA', 'N':' AAA A',
                    'O':' AAA AAA AAA', 'P':' A AAA AAA A', 'Q':' AAA AAA A AAA',
                    'R':' A AAA A', 'S':' A A A', 'T':' AAA',
                    'U':' A A AAA', 'V':' A A A AAA', 'W':' A AAA AAA',
                    'X':' AAA A A AAA', 'Y':' AAA A AAA AAA', 'Z':' AAA AAA A A',
                    '1':' A AAA AAA AAA AAA', '2':' A A AAA AAA AAA', '3':' A A A AAA AAA',
                    '4':' A A A A AAA', '5':' A A A A A', '6':' AAA A A A A',
                    '7':' AAA AAA A A A', '8':' AAA AAA AAA A A', '9':' AAA AAA AAA AAA A',
                    '0':' AAA AAA AAA AAA AAA', ',':' AAA AAA A A AAA AAA', '.':' A AAA A AAA A AAA',
                    '?':' A A AAA AAA A A', '/':' AAA A A AAA A', '-':' AAA A A A A AAA',
                    '(':'-.--.', ')':' AAA A AAA AAA A AAA', ";": " A AAA AAA A AAA AAA",
                    ":": "AAA AAA AAA A A A", "!": " AAA A AAA A AAA AAA",
                    "[": "AAA A AAA A A AAA", "]":"AAA AAA A A", "&":"A AAA A A A"
                       }
    AAAAA_code_DICT_lower = {
        'a': 'A AAA', 'b': 'AAA A A A ',
        'c': ' AAA A AAA A', 'd': ' AAA A A', 'e': ' A',
        'f': ' A A AAA A', 'g': ' AAA AAA A', 'h': ' A A A A',
        'i': ' A A', 'j': ' A AAA AAA AAA', 'k': ' AAA A AAA',
        'l': ' A AAA A A', 'm': ' AAA AAA', 'n': ' AAA A',
        'o': ' AAA AAA AAA', 'p': ' A AAA AAA A', 'q': ' AAA AAA A AAA',
        'r': ' A AAA A', 's': ' A A A', 't': ' AAA',
        'u': ' A A AAA', 'v': ' A A A AAA', 'w': ' A AAA AAA',
        'x': ' AAA A A AAA', 'y': ' AAA A AAA AAA', 'z': ' AAA AAA A A',
        '1': ' A AAA AAA AAA AAA', '2': ' A A AAA AAA AAA', '3': ' A A A AAA AAA',
        '4': ' A A A A AAA', '5': ' A A A A A', '6': ' AAA A A A A',
        '7': ' AAA AAA A A A', '8': ' AAA AAA AAA A A', '9': ' AAA AAA AAA AAA A',
        '0': ' AAA AAA AAA AAA AAA', ',': ' AAA AAA A A AAA AAA', '.': ' A AAA A AAA A AAA',
        '?': ' A A AAA AAA A A', '/': ' AAA A A AAA A', '-': ' AAA A A A A AAA',
        "'": ' A AAA AAA AAA AAA A', ":": "AAA AAA AAA A A A",
        '(': '-.--.', ')': ' AAA A AAA AAA A AAA',
        ";": " A AAA AAA A AAA AAA",
        "!": " AAA A AAA A AAA AAA", "[" : "AAA A AAA A A AAA", "]": "AAA AAA A A","&":"A AAA A A A",
        "_": "AAA A A A AAA", "=":"AAAAAAA"
    }
    ciphered = ""
    if filename == None:
     for letter in message:
        letter_check = letter.isupper()
        if (letter != " ") and (letter_check==True):
            ciphered += AAAAA_code_DICT_upper[letter] + " "
        elif (letter != " ") and (letter_check==False):
            ciphered += AAAAA_code_DICT_lower[letter] + " "
        else:
            # 1 space indicates different characters
            # and 2 indicates different words
            ciphered += " "
        print(ciphered)
    elif filename != None:
      with open(filename, "r") as file:
          file_data = file.read()
          file.close()
      for letter in file_data:
          #Side note, ; is equal to .--.-- This is not a valid morse code, but it is valid on AAAArse code alphabet.
          #Check line 54.
          # [ is equal to AAA A AAA A A AAA. -.-..-
          # ] is equal to AAA AAA A A. --.. It might be valid for something on morse alphabet but fuck it.
          letter_check = letter.isupper()
          if (letter != " ") and (letter_check == True) and (letter != "\n") and (letter != "|"):
              ciphered += AAAAA_code_DICT_upper[letter] + " "
          elif (letter != " ") and (letter_check == False) and (letter != "\n") and (letter != "|"):
              ciphered += AAAAA_code_DICT_lower[letter] + " "
          elif letter == "\n":
              ciphered += "\n"
          elif letter == "|":
              ciphered += "|"
          else:
              ciphered += " "
      with open(filename, "w") as file:
          file.write(ciphered)
def get_original_extension_of_file(foldername: object, key: object) -> object:
    files = Path(foldername).glob("*")
    global original_extension
    with open("extension.txt","w") as file2:
        for file in files:
            file_name, file_extension = os.path.splitext(file)
            original_extension = file_extension
        file2.write(original_extension)
    return original_extension
def convert_to_AAAA_in_folder(foldername):
    AAAAA_code_DICT_upper = {
        'A': 'A AAA', 'B': 'AAA A A A ',
        'C': ' AAA A AAA A', 'D': ' AAA A A', 'E': ' A',
        'F': ' A A AAA A', 'G': ' AAA AAA A', 'H': ' A A A A',
        'I': ' A A', 'J': ' A AAA AAA AAA', 'K': ' AAA A AAA',
        'L': ' A AAA A A', 'M': ' AAA AAA', 'N': ' AAA A',
        'O': ' AAA AAA AAA', 'P': ' A AAA AAA A', 'Q': ' AAA AAA A AAA',
        'R': ' A AAA A', 'S': ' A A A', 'T': ' AAA',
        'U': ' A A AAA', 'V': ' A A A AAA', 'W': ' A AAA AAA',
        'X': ' AAA A A AAA', 'Y': ' AAA A AAA AAA', 'Z': ' AAA AAA A A',
        '1': ' A AAA AAA AAA AAA', '2': ' A A AAA AAA AAA', '3': ' A A A AAA AAA',
        '4': ' A A A A AAA', '5': ' A A A A A', '6': ' AAA A A A A',
        '7': ' AAA AAA A A A', '8': ' AAA AAA AAA A A', '9': ' AAA AAA AAA AAA A',
        '0': ' AAA AAA AAA AAA AAA', ',': ' AAA AAA A A AAA AAA', '.': ' A AAA A AAA A AAA',
        '?': ' A A AAA AAA A A', '/': ' AAA A A AAA A', '-': ' AAA A A A A AAA',
        '(': '-.--.', ')': ' AAA A AAA AAA A AAA', ";": " A AAA AAA A AAA AAA",
        ":": "AAA AAA AAA A A A", "!": " AAA A AAA A AAA AAA",
        "[": "AAA A AAA A A AAA", "]": "AAA AAA A A", "&": "A AAA A A A"
    }
    AAAAA_code_DICT_lower = {
        'a': 'A AAA', 'b': 'AAA A A A ',
        'c': ' AAA A AAA A', 'd': ' AAA A A', 'e': ' A',
        'f': ' A A AAA A', 'g': ' AAA AAA A', 'h': ' A A A A',
        'i': ' A A', 'j': ' A AAA AAA AAA', 'k': ' AAA A AAA',
        'l': ' A AAA A A', 'm': ' AAA AAA', 'n': ' AAA A',
        'o': ' AAA AAA AAA', 'p': ' A AAA AAA A', 'q': ' AAA AAA A AAA',
        'r': ' A AAA A', 's': ' A A A', 't': ' AAA',
        'u': ' A A AAA', 'v': ' A A A AAA', 'w': ' A AAA AAA',
        'x': ' AAA A A AAA', 'y': ' AAA A AAA AAA', 'z': ' AAA AAA A A',
        '1': ' A AAA AAA AAA AAA', '2': ' A A AAA AAA AAA', '3': ' A A A AAA AAA',
        '4': ' A A A A AAA', '5': ' A A A A A', '6': ' AAA A A A A',
        '7': ' AAA AAA A A A', '8': ' AAA AAA AAA A A', '9': ' AAA AAA AAA AAA A',
        '0': ' AAA AAA AAA AAA AAA', ',': ' AAA AAA A A AAA AAA', '.': ' A AAA A AAA A AAA',
        '?': ' A A AAA AAA A A', '/': ' AAA A A AAA A', '-': ' AAA A A A A AAA',
        "'": ' A AAA AAA AAA AAA A', ":": "AAA AAA AAA A A A",
        '(': '-.--.', ')': ' AAA A AAA AAA A AAA',
        ";": " A AAA AAA A AAA AAA",
        "!": " AAA A AAA A AAA AAA", "[": "AAA A AAA A A AAA", "]": "AAA AAA A A", "&": "A AAA A A A"
    }
    ciphered = ""
    files = Path(foldername).glob("*")
    for filename in files:
      if(filename != None):
       with open(filename, "r") as file:
          file_data = file.read()
          file.close()
       for letter in file_data:
          letter_check = letter.isupper()
          if (letter != " ") and (letter_check == True) and (letter != "\n") and (letter != "|"):
              ciphered += AAAAA_code_DICT_upper[letter] + " "
          elif (letter != " ") and (letter_check == False) and (letter != "\n") and (letter != "|"):
              ciphered += AAAAA_code_DICT_lower[letter] + " "
          elif letter == "\n":
              ciphered += "\n"
          elif letter == "|":
              ciphered += "|"
          else:
              ciphered += " "
       with open(filename, "w") as file:
          file.write(ciphered)
def load_extension():
    return open("extension.txt","r").read()
def change_extensions_in_folder(foldername,key):
    files = Path(foldername).glob("*")
    for file in files:
        base = os.path.splitext(file)[0]
        os.rename(file, base + ".AAAAA")
def decrypt_in_folder(foldername,key,original_extension):
    files = Path(foldername).glob("*")
    for file in files:
        base = os.path.splitext(file)[0]
        os.rename(file, base + original_extension)
def hill_encryption(plain, key):
    #Add a zero for every odd number
    global encrypted_text
    global mule_inv
    len_chk=0
    if ((len(plain)%2) != 0):
        plain += "0"
        len_chk = 1
    #Create Hill 2x2 matrixes
    row = 2
    col = int(len(plain)/2)
    msg2d = np.zeros((row,col), dtype=int)
    itr1 = 0
    itr2 = 0
    for i in range ((len(plain))):
        if (i%2==0):
            msg2d[0][itr1] = int(ord(plain[i])-65)
            itr1 += 1
        else:
            msg2d[0][itr2] = int(ord(plain[i])-65)
            itr2 += 1
    #Create a key
    key2d = np.zeros((2,2), dtype=int)
    itr3 = 0
    for i in range(2):
        for j in range(2):
            key2d[i][j] = ord(key[itr3])-65
            itr3 += 1
    print(key2d)
    #Check validity of the key, first find determinant
    deter = key2d[0][0] * key2d[0][1] * key2d [1][0] * key2d [1][1]
    deter = deter % 26
    mule_inv = 0
    #Find multiplicative inverse
    for i in range(26):
        temp_inv = deter*i
        if temp_inv % 26 == 1:
            mule_inv = i
            break
        else:
            continue

    if mule_inv == -1:
        print("Invalid key")
        sys.exit()
    encrypted_text = ""
    itr_count = int(len(plain)/2)
    if len_chk == 0:
        for i in range(itr_count):
            temp1 = (msg2d[0][i] * key2d[0][0]) + (msg2d[1][i]*key2d[0][1])
            encrypted_text += chr((temp1%26)+65)
            temp2 = (msg2d[0][i] * key2d[1][0]) + (msg2d[1][i]*key2d[1][1])
            encrypted_text += chr((temp2%26)+65)
    else:
        for i in range(itr_count-1): #Subtract 1 zero we added above
            temp1 = (msg2d[0][i] * key2d[0][0]) + (msg2d[1][i]*key2d[0][1])
            encrypted_text += chr((temp1%26)+65)
            temp2 = (msg2d[0][i] * key2d[1][0]) + (msg2d[1][i]*key2d[1][1])
            encrypted_text += chr((temp2%26)+65)
    print("Encrypted text: {} ".format(encrypted_text))
    return encrypted_text
def A10_decryption(cipher,key):
    global mule_inv
    len_chk = 0
    if (len(cipher)%2) != 0:
        cipher += "0"
        len_chk = 1
    row = 2
    column = int(len(cipher)/2)
    msg2d = np.zeros((row,column), dtype=int)
    itr1 = 0
    itr2 = 0
    for i in range(len(cipher)):
        if i%2==0:
            msg2d[0][itr1] = int(ord(cipher[i])-65)
            itr1 += 1
        else:
            msg2d[1][itr2] = int(ord(cipher[i])-65)
            itr2 +=1
    #Create a key
    key2d = np.zeros((2,2), dtype=int)
    itr3 = 0
    for i in range(2):
        for j in range(2):
            key2d[i][j] = ord(key[itr3]) - 65
            itr3 += 1
    #Find determinant
    deter = key2d[0][0]*key2d[1][1] - key2d[0][1] * key2d[1][0]
    deter = deter % 26
    #Find multiplicative inverse
    for i in range(26):
        temp_inv = deter*i
        if (temp_inv%26) == 1:
            mule_inv = i
            break
        else:
            continue
    #Adjugate matrix
    #swapping
    key2d[0][0],key2d[1][1] = key2d[1][1], key2d[0][0]
    #change signs
    key2d[0][1] *= -1
    key2d[1][0] *= -1
    key2d[0][1] = key2d[0][1] % 26
    key2d[1][0] = key2d[1][0] % 26
    mule_inv=0
    for i in range(2):
        for j in range(2):
            key2d[i][j] *= mule_inv
    for i in range(2):
        for j in range(2):
            key2d[i][j] = key2d[i][j] % 26
    decrypt_text = ""
    iteration_count=int(len(cipher)/2)
    if len_chk == 0:
        for i in range(iteration_count):
            temp1 = msg2d[0][i] * key2d[0][0] + msg2d[1][i] * key2d[0][1]
            decrypt_text += chr((temp1 % 26) + 65)
            temp2 = msg2d[0][i] * key2d[1][0] + msg2d[1][i] * key2d[1][1]
            decrypt_text += chr((temp2 % 26) + 65)
    else:
        for i in range(iteration_count-1):
            temp1 = msg2d[0][i] * key2d[0][0] + msg2d[1][i] * key2d[0][1]
            decrypt_text += chr((temp1 % 26) + 65)
            temp2 = msg2d[0][i] * key2d[1][0] + msg2d[1][i] * key2d[1][1]
            decrypt_text += chr((temp2 % 26) + 65)
    print("Decrypted text> {}".format(decrypt_text))
    print("and it is time for BEHEADED KAMIKAZE!...")
    # playsound("Serious Sam Kamikaze scream.wav")
class FileOfType:
    def __init__(self, type):
        self.type = type
        assert type in ['dir', 'file']
    def __call__(self, path):
        if self.type == 'dir':
            if not os.path.isdir(path):
                raise argparse.ArgumentTypeError(f"{path} is not a directory")
        elif self.type == 'file':
            if not os.path.isfile(path):
                raise argparse.ArgumentTypeError(f"{path} is not a regular file")
            elif os.path.islink(path):
                raise argparse.ArgumentTypeError(f"{path} is a symbolic link")
        return path
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Change every file extension to .AAAAA in folder")
    parser.add_argument("-dir","--directory", type=FileOfType("dir"))
    parser.add_argument("-ge","-getextension",action="store_true",help="Gets extension of files in folders to decrypt in the future")
    parser.add_argument("-g", "--generate-key", dest="generate_key", action="store_true",
                        help="Whether to generate a new key or use existing")
    parser.add_argument("-e","--encrypt",action="store_true",help="Encrypts every file with .AAAAA extension key")
    parser.add_argument("-d","--decrypt",action="store_true",help="Decrypts every file with .AAAAA extension key")
    parser.add_argument("-f","--file",type = FileOfType("file"))
    parser.add_argument("-et","--encrypttext",action="store_true",help="Encrypts a .txt file with .AAAAA alphabet.")
    parser.add_argument("-nsdir","--notsuredir", type=FileOfType("dir"), help="Use this dir option if you have many subfolders in that directory")
    args = parser.parse_args()
    print(args)
generate_key = args.generate_key
if generate_key:
     write_key()
key = load_key()
getextension_ = args.ge
if getextension_:
    directory = args.directory
    get_original_extension_of_file(directory, key)
original_extension = load_extension()
directory_ = args.directory
encrypt_ = args.encrypt
decrypt_ = args.decrypt
directory = args.directory
file = args.file
encrypttext_ = args.encrypttext
dir2 = args.notsuredir
if (directory_ != None) and (encrypt_ == True):
    change_extensions_in_folder(directory,key)
elif (directory_ != None) and (decrypt_ == True):
    decrypt_in_folder(directory, key, original_extension)

if encrypttext_ == True:
    print("Please enter a string to encrypt, leave this blank if you want to encrypt a .txt file")
    message = input()
    convert_txt_to_morse_AAAA(message,file)
if (directory_ != None) and encrypttext_ == True:
    convert_to_AAAA_in_folder(directory)
if (dir2 != None) and encrypttext_ == True:
 for root, dirs, files in os.walk(directory):
    for dirname in dirs:
        convert_to_AAAA_in_folder(os.path.join(root, dirname))
        change_extensions_in_folder(directory,key)

plaintext = "fuck..."
plaintext = plaintext.upper().replace(" ","")
key = "hill"
key = key.upper().replace(" ","")
ciphertext = hill_encryption(plaintext, key)
