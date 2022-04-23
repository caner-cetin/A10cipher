import json
import os
import sys
import os
import argparse
from pathlib import Path
import time


class Encryptor():
    def __init__(self):
        self.AAAAA_code_DICT_lower = {
            'a': 'Aa0AAA', 'b': 'AA0A0A0A0A',
            'c': 'AAA0A0AAA0A', 'd': 'AAA0A0A', 'e': 'A10AA0A0AAAAAAAAA',
            'f': 'A0A0AAA0A', 'g': 'AAA0AAA0A', 'h': 'Aa10A0A0A',
            'i': 'AA0A', 'j': 'aA0AAA0AAA0AAA', 'k': 'AAA0A0AAA',
            'l': 'A0AAA0A0A', 'm': 'AAA0AAA', 'n': 'AAA0AAAA',
            'o': 'AAA0AAA0AAA', 'p': 'A0AAA0AAA0A', 'q': 'AAA0AAA0A0AAA',
            'r': 'A0AAA0A', 's': 'A0A0A', 't': 'AAA',
            'u': 'A0A0AAA', 'v': 'A0A0A0AAA', 'w': 'A0AAA0AAA',
            'x': 'AA0AA0A0AAA', 'y': 'AAAa0A0AAA0A0AA', 'z': 'AAA0AAA0AAAA0A',
            '1': 'A0AAA0AAA0AAA0AAA', '2': 'A0A0AAA0AAA0AAA', '3': 'A0A0A0AAA0AAA',
            '4': 'A0A0A0A0AAA', '5': 'A0A0A0A0A', '6': 'AAA0A0A0A0A',
            '7': 'AAA0AAA0A0A0A', '8': 'AAA0AAA0AAA0A0A', '9': 'AAA0AAA0AAA0AAA0A',
            '0': 'AAA0AAA0AAA0AAA0AAA', ',': 'AAA0AAA0A0A0AAA0AAA', '.': 'A0AA0aA0A0AAA0A0AAA',
            '?': 'A0A0AAA0AAA0A0A', '/': 'AAA0A0A0AAA0A', '-': 'AAA0A0A0A0A0AAA',
            "'": 'A0AAA0AAA0AAA0AAA0A', ":": "AAA0AAA0AAA0A0A0A",
            '(': '-.--.', ')': '0AAaAa0A0AAA0AAA0A0AAA',
            ";": "0A0AAA0AAaAa0A0AAA0AAA",
            "!": "0AA0A0AaaAA0A0AAA0AAA", "[": "AAA0aA0AAA0A0A0AAA", "]": "AAA0AAA0A0A", "&": "A0AAA0A0A0A",
            "_": "AAA0A0A0A0AAA", "=": "AAAAAAA"
        }
        self.AAAAA_code_DICT_upper = {k.upper():v for k,v in self.AAAAA_code_DICT_lower.items()}
        self.lowerinverted = {v: k for k, v in self.AAAAA_code_DICT_lower.items()}
        self.upperinverted = {v: k for k, v in self.AAAAA_code_DICT_upper.items()}


    def decrypt_msg(self, msg):
        lowerdict = self.lowerinverted
        upperdict = self.upperinverted
        s = ""
        deciphered = ""
        y = msg.split(" ")
        print(y)
        for s in y:
            if "\n" in s:
                deciphered += "\n"
                placeholder = s.replace("\n", "")
                s = placeholder
            else:
                pass
            if s in lowerdict.keys():
                deciphered += lowerdict[s]
            elif s in upperdict.keys():
                deciphered += upperdict[s]
            if s == "|":
                deciphered += "|"
            s = ""
        print(deciphered)
        return deciphered

    def encrypt_msg(self, msg):
        lowerdict = self.lowerinverted
        upperdict = self.upperinverted
        s = ""
        deciphered = ""
        y =msg.split(" ")
        print(y)
        for s in y:
            if "\n" in s:
                deciphered += "\n"
                placeholder = s.replace("\n", "")
                s = placeholder
            else:
                pass
            if s in lowerdict.keys():
                deciphered += lowerdict[s]
            elif s in upperdict.keys():
                deciphered += upperdict[s]
            if s == "|":
                deciphered += "|"
            s = ""
        print(deciphered)
        return deciphered

    def encrypt_file(self, file_name, path):
        lowerdict = self.AAAAA_code_DICT_lower
        upperdict = self.AAAAA_code_DICT_upper
        ciphered = ""
        for letter in file_name:
            # Side note, ; is equal to .--.-- This is not a valid morse code, but it is valid on AAAArse code alphabet.
            # Check line 54.
            # [ is equal to AAA A AAA A A AAA. -.-..-
            # ] is equal to AAA AAA A A. --.. It might be valid for something on morse alphabet but fuck it.
            letter_check = letter.isupper()
            if (letter != " ") and (letter_check == True) and (letter != "\n") and (letter != "|"):
                ciphered += upperdict[letter] + " "
            elif (letter != " ") and (letter_check == False) and (letter != "\n") and (letter != "|"):
                ciphered += lowerdict[letter] + " "
            elif letter == "\n":
                ciphered += "\n"
            elif letter == "|":
                ciphered += "|"
            else:
                ciphered += ""
        print(ciphered)
        with open(path, "w") as f:
            f.write(ciphered)

    def decrypt_file(self, file_data, path):
        lowerdict = self.lowerinverted
        upperdict = self.upperinverted
        s = ""
        deciphered = ""
        y = file_data.split(" ")
        print(y)
        for s in y:
            if "\n" in s:
                deciphered += "\n"
                placeholder = s.replace("\n", "")
                s = placeholder
            else:
                pass
            if s in lowerdict.keys():
                    deciphered += lowerdict[s]
            elif s in upperdict.keys():
                    deciphered += upperdict[s]
            if s == "|":
                deciphered += "|"
            s = ""
        print(deciphered)
        with open(path, "w") as f:
            f.write(deciphered)
        return deciphered


def get_original_extension_of_file(foldername: object, key: object) -> object:
    files = Path(foldername).glob("*")
    global original_extension
    with open("extension.txt", "w") as file2:
        for file in files:
            file_name, file_extension = os.path.splitext(file)
            original_extension = file_extension
        file2.write(original_extension)
    return original_extension


def encrypt_txt_files(dir):
    # Find subfolders
    for folder in os.listdir(dir):
        if os.path.isdir(folder):
            # Find files in subfolders
            for file in os.listdir(folder):
                if file.endswith(".txt"):
                    # Encrypt files
                    encryptor = Encryptor()
                    # Get path of the file
                    path = os.path.join(folder, file)
                    with open(path, "r") as f:
                        file_data = f.read()
                    encryptor.encrypt_file(file_data, path)


def decrypt_txt_files():
    # Find subfolders
    for folder in os.listdir(os.getcwd()):
        if os.path.isdir(folder):
            # Find files in subfolders
            for file in os.listdir(folder):
                if file.endswith(".txt"):
                    # Encrypt files
                    encryptor = Encryptor()
                    # Get path of the file
                    path = os.path.join(folder, file)
                    with open(path, "r") as f:
                        file_data = f.read()
                    encryptor.decrypt_file(file_data, path)


def change_extensions_in_folder(foldername, key):
    files = Path(foldername).glob("*")
    for file in files:
        base = os.path.splitext(file)[0]
        os.rename(file, base + ".AAAAA")
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
    parser.add_argument("-dir", "--directory", type=FileOfType("dir"))
    parser.add_argument("-ge", "-getextension", action="store_true",
                        help="Gets extension of files in folders to decrypt in the future")
    parser.add_argument("-g", "--generate-key", dest="generate_key", action="store_true",
                        help="Whether to generate a new key or use existing")
    parser.add_argument("-e", "--encrypt", action="store_true", help="Encrypts every txt file with AAAA alphabet")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Decrypts every txt file with AAAA alphabet")
    parser.add_argument("-f", "--file", type=FileOfType("file"))
    args = parser.parse_args()
if len(sys.argv) < 2:
    encrypt_txt_files()
    time.sleep(30)
    decrypt_txt_files()
generate_key = args.generate_key
directory_ = args.directory
encrypt_ = args.encrypt
decrypt_ = args.decrypt
directory = args.directory
file = args.file
encrypttext_ = args.encrypttext

if encrypttext_ == True:
    print("Please enter a string to encrypt, leave this blank if you want to encrypt a .txt file")
    message = input()
if (directory_ != None) and encrypttext_ == True:
    encrypt_txt_files(directory_)
if (directory_ != None) and decrypt_ == True:
    decrypt_txt_files(directory_)
if (file != None) and encrypttext_ == True:
    encryptor = Encryptor()
    with open(file, "r") as f:
        file_data = f.read()
    # Get path of file
    path = os.path.join(file)
    encryptor.encrypt_file(file_data, path)
if (file != None) and decrypt_ == True:
    encryptor = Encryptor()
    with open(file, "r") as f:
        file_data = f.read()
    # Get path of file
    path = os.path.join(file)
    encryptor.decrypt_file(file_data, path)
