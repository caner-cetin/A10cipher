import argparse
import json
import os
import sys
import tkinter as tk
from os.path import isfile
from tkinter import filedialog
import portalocker
import click
class Encryptor():
    def __init__(self):
        self.AAAAA_code_DICT_lower = {
            'a': 'Aa0AAA', 'b': 'AA0A0A0A0A',
            'c': 'AAA0A0AAA0A', 'd': 'AAA0A0A', 'e': 'A10AA0A0AAA',
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
            "_": "AAA0A0A0A0AAA", "=": "AAAAAAA", '"': "A0AAA0AAA0AAA0AAA0A0A", '{': "AAA0A0A0A0A0A",
            '\\': "AAA0A0A0A0A0AAA", '}': "AAA0A0A0A0A0A0A", '@': "A0AAA0A0A0A0A0A0A0A", '#': "A0AAA0A0A0A0A0A0A0A0A",
            '$': "A0AAA0A0A0A0A0A0A0A0A0A", '%': "A0AAA0A0A0aaA0A", '^': "A0AAA0A0A0A0A0A0A0A0A0A0A0A",
            '&': "A0AaaaAa0A0A0A", '*': "A0AAA0A0A0A0A0aaaaA0A0A0A0A0A0A", '+': "A0AAAaaaAAaa0A0A0A0A0A0A",
            '~': "A0AAaaaAA0A0A0A0A0A", '`': "A0AAA0A0AaaAa", '<': "AAA0A0A0aA0A0A0A0A0A0a",
            "â": "A0a0a0AA", "€": "aaaaa00"
        }
        self.AAAAA_code_DICT_upper = {
            'A': 'A0AAA', 'B': 'AAA0A0A0A0',
            'C': '0AAA0A0AAA0A', 'D': '0AAA0A0A', 'E': '0A',
            'F': '0A0A0AAA0A', 'G': '0AAA0AAA0A', 'H': '0A0A0A0A',
            'I': '0A0A', 'J': '0A0AAA0AAaA0AAA', 'K': '0AAA0A0AAA',
            'L': '0A0AAA0A0A', 'M': '0AAA0AAA', 'N': '0AAA0A',
            'O': '0AAA0AAA0AAA', 'P': '0aA0AAA0AAA0A', 'Q': '0AAA0AAA0A0AAA',
            'R': '0A0AAA0A', 'S': '0A0A0A', 'T': '0AAA',
            'U': '0A0A0AAA', 'V': '0A0A0A0AAA', 'W': '0A0AAA0AAA',
            'X': '0AAA0A0A0AAA', 'Y': '0AAA0A0AAA0AAA', 'Z': '0AAA0AAA0A0A',
            '1': '0A0AAaA0AAA0AAA0AAA', '2': '0A0aA0AAA0AAA0AAA', '3': '0A0A0A0AAA0AAA',
            '4': '0A0A0A0A0AAA', '5': '0A0A0A0A0A', '6': '0AAA0A0A0A0A',
            '7': '0AAA0AAA0A0A0A', '8': '0AAA0AAA0AAA0A0A', '9': '0AAA0AAA0AAA0AAA0A',
            '0': '0AAA0AAA0AAA0AAA0AAA', ',': '0AAA0AAA0A0A0AAA0AAA', '.': '0A0AAA0A0AAA0A0AAA',
            '?': '0A0aA0AAA0AAA0A0A', '/': '0AAA0A0A0AAA0A', '-': '0AAA0A0A0A0A0AAA',
            '(': '-.--.', ')': '0AAA0aA0AAA0AAA0Aa0AAA', ";": "a0A0AAA0aAAA0A0AAA0AAA",
            ":": "AAA0AAA0AAA0A0A0A", "!": "0AAA0A0AAA0A0AAA0AAA",
            "[": "AAA0A0AAA0A0A0AAA", "]": "AAA0AAA0A0A", "&": "A0AAA0A0A0A"
        }
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
            if "NEW_WORD" in s:
                deciphered += " "
                placeholder = s.replace("NEW_WORD", "")
                s = placeholder
            if s in lowerdict.keys():
                deciphered += lowerdict[s]
            elif s in upperdict.keys():
                deciphered += upperdict[s]
            if s == "|":
                deciphered += "|"
            if y.index(s) == len(y) - 1:
                deciphered += " "
            s = ""
        print(deciphered)
        return deciphered

    def encrypt_msg(self, msg):
        lowerdict = self.AAAAA_code_DICT_lower
        upperdict = self.AAAAA_code_DICT_upper
        s = ""
        ciphered = ""
        y = msg.split(" ")
        print(y)
        for letter in msg:
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
                ciphered += "00"
        print(ciphered)
        return ciphered

    def encrypt_file(self, file_name, path):
        lowerdict = self.AAAAA_code_DICT_lower
        upperdict = self.AAAAA_code_DICT_upper
        ciphered = ""
        y = file_name.split(" ")
        for words in y:
            ciphered += "NEW_WORD"
            for letter in words:
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
        with open(path, "w") as f:
            f.write(ciphered)

    def decrypt_file(self, file_data, path):
        lowerdict = self.lowerinverted
        upperdict = self.upperinverted
        s = ""
        deciphered = ""
        y = file_data.split(" ")
        for s in y:
            if "\n" in s:
                deciphered += "\n"
                placeholder = s.replace("\n", "")
                s = placeholder
            if "NEW_WORD" in s:
                deciphered += " "
                placeholder = s.replace("NEW_WORD", "")
                s = placeholder
            else:
                pass
            if s in lowerdict.keys():
                deciphered += lowerdict[s]
            elif s in upperdict.keys():
                deciphered += upperdict[s]
            if s == "|":
                deciphered += "|"
        with open(path, "w") as f:
            f.write(deciphered)
        print("Decryption is done!")
        return deciphered


def change_file_extension(file, new_extension):
    # Get old extension of file for replacing later
    old_extension = file.split(".")[-1]
    # Get file name without extension
    file_name = file.split(".")[0]
    # Replace .AAAA as a new extension
    new_file_name = file_name + "." + new_extension
    # Overwrite old file with new file
    os.rename(file, new_file_name)
    z = file.split(old_extension)
    # Add .AAAAA to the end of the z
    new_file_path = z[0] + new_extension
    # Store old file name without extension and old extension in a new dictionary
    file_dict = {new_file_path: old_extension}
    exportlist = []
    exportlist.append(file_dict)
    # Return new file name
    return new_file_name, exportlist


def encrypt_txt_folder(dir):
    # Iterate through every file in the directory
    for file in os.listdir(dir):
        # If the file is a .txt file
        if file.endswith(".txt"):
            # Get path of file
            path = os.path.join(dir, file)
            # Open the file in read mode
            with open(path, "r") as f:
                # Read the contents of the file
                data = f.read()
                # Encrypt the contents of the file
                # Get path of the file
                y = Encryptor()
                y.encrypt_file(data, path)

def encrypt_txt_files(file):
    encryptor = Encryptor()
    with open(file, "r") as f:
        file_data = f.read()
    encryptor.encrypt_file(file_data, file)


def encrypt_messages(message):
    encryptor = Encryptor()
    ciphered = encryptor.encrypt_msg(message)
    with open("message.txt", "w") as f:
        f.write(ciphered)
    return ciphered


def decrypt_txt_folder(dir):
    if os.path.isdir(folder):
        # Find files in subfolders
        for file in os.listdir(folder):
            if file.endswith(".txt"):
                print("Now encrypting {}".format(file))
                # Encrypt files
                encryptor = Encryptor()
                # Get path of the file
                path = os.path.join(folder, file)
                with open(path, "r") as f:
                    file_data = f.read()
                encryptor.decrypt_file(file_data, path)


def decrypt_messages(message):
    encryptor = Encryptor()
    deciphered = encryptor.decrypt_msg(message)
    print(deciphered)
    with open("message.txt", "w") as f:
        f.write(deciphered)
    return deciphered


def decrypt_txt_file(file):
    encryptor = Encryptor()
    with open(file, "r") as f:
        file_data = f.read()
    encryptor.decrypt_file(file_data, file)


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
    flag = True
    while flag == True:
        print("Please enter a command")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Exit")
        choice = input()
        if choice == "1":
            print("Please choose if you want to encrypt a file or a folder")
            print("1. File")
            print("2. Folder")
            print("3. Single Message")
            choice = input()
            if choice == "1":
                root = tk.Tk()
                root.withdraw()
                root.title("Please choose a file")
                file_path = filedialog.askopenfilename()
                print("Encrypting file {}".format(file_path))
                encrypt_txt_files(file_path)
                print("File encrypted")
                resultlist = []
                test, list = change_file_extension(file_path, "AAAAA")
                resultlist.append(list)
                print("Would you like to encrypt the following files? (y/n)")
                # Get directory of file_path
                dir_path = os.path.dirname(file_path)
                files = os.listdir(dir_path)
                for i in files:
                    print(i)
                choice = input()
                base = os.path.basename(file_path)
                json_name = base + ".json"
                file_dir = os.path.dirname(file_path)
                os.chdir(file_dir)
                if choice == "y":
                    for i in files:
                        if os.access(i, os.W_OK):
                            if json_name in i:
                                print("{} is a config file for decryption. Skipping.".format(i))
                                continue
                            if i.endswith(".AAAAA"):
                                print("File {} already encrypted".format(i))
                            else:
                                print("Encrypting file {}".format(i))
                                encrypt_txt_files(i)
                                print("File {} encrypted".format(i))
                                # Get path of i
                                path = os.path.join(file_dir, i)
                                test, list = change_file_extension(path, "AAAAA")
                                print("File " + i + " extension changed")
                                resultlist.append(list)
                        else:
                            print("düt")
                    print("Files listed encrypted")
                else:
                    pass
                os.chdir(file_dir)
                with open(json_name, "w") as f:
                    f.write(json.dumps(resultlist))
                print("PLEASE DO NOT DELETE THE JSON FILE FOR FUTURE DECRYPTION")
                print("Encryption complete")
                print("Press 3 to exit, press 2 to return to main menu")
                choice = input()
                if choice == "3":
                    flag = False
                elif choice == "2":
                    flag = True
            elif choice == "2":
                root = tk.Tk()
                root.withdraw()
                folder_path = filedialog.askdirectory()
                print("Do you want subdirectories too or no?, just press 1 for yes or 2")
                choice = int(input())
                if choice == 1:
                    resultlist = []
                    print("Result list created...")
                    subfolders = [f.path for f in os.scandir(folder_path) if f.is_dir()]
                    print("Subfolders scanned...")
                    for subfolder in subfolders:
                        print("Encrypting files in " + subfolder)
                    for subfolder in subfolders:
                        # Get files in subfolders
                        files = [f.path for f in os.scandir(subfolder) if f.is_file()]
                        print("Files in " + subfolder + " scanned...")
                        for file in files:
                            # Get directory of file
                            file_dir = os.path.dirname(file)
                            os.chdir(file_dir)
                            print("Encrypting file " + file)
                            encrypt_txt_files(file)
                            print("File " + file + " encrypted")
                            test, list = change_file_extension(file, "AAAAA")
                            print("File " + file + " extension changed")
                            resultlist.append(list)
                        # Get dir name
                        dir_name = os.path.basename(subfolder)
                        os.chdir(subfolder)
                        json_name = dir_name + "_ext.json"
                        with open(json_name, "w") as f:
                            f.write(json.dumps(resultlist))
                    resultlist = []
                    # Scan base directory
                    files = [f.path for f in os.scandir(folder_path) if f.is_file()]
                    for file in files:
                        encrypt_txt_files(file)
                        test, list = change_file_extension(file, "AAAAA")
                        resultlist.append(list)
                    basedir_name = os.path.basename(folder_path)
                    json_base_name = basedir_name + "_ext.json"
                    os.chdir(folder_path)
                    with open(json_base_name, "w") as f:
                        f.write(json.dumps(resultlist))
                    print("Encryption complete")
                    print("PLEASE DO NOT DELETE THE JSON FILE FOR FUTURE DECRYPTION")
                    print("Press 3 to exit, press 2 to return to main menu")
                    choice = input()
                    if choice == "3":
                        flag = False
                    elif choice == "2":
                        flag = True
                elif choice == 2:
                    # Iterate through every file on folder_path with scandir
                    files = [f.path for f in os.scandir(folder_path) if f.is_file()]
                    print("Files scanned...")
                    resultlist = []
                    for file in files:
                        print("Encrypting file " + file)
                        encrypt_txt_files(file)
                        print("File " + file + " encrypted")
                        test, list = change_file_extension(file, "AAAAA")
                        print("File " + file + " extension changed")
                        resultlist.append(list)
                    os.chdir(folder_path)
                    # Get name of folder
                    folder_name = os.path.basename(folder_path)
                    extension_json = folder_name + ".json"
                    with open(extension_json, "w") as f:
                        f.write(json.dumps(resultlist))
                    print("Encryption complete")
                    print("Press 3 to exit, press 2 to return to main menu")
                    choice = input()
                    if choice == "3":
                        flag = False
                    elif choice == "2":
                        flag = True
            elif choice == "3":
                initial_message = "Enter the message you want to encrypt, save and close the editor when you are done."
                edited_message = click.edit(initial_message)
                encrypt_messages(edited_message)
                # Change extension when done
                change_file_extension("message.txt", "AAAAA")
                print("Encryption complete, encrypted text is in the file 'message.AAAAA'")
                print("Press 3 to exit, press 2 to return to main menu")
                choice = input()
                if choice == "3":
                    flag = False
                elif choice == "2":
                    flag = True
            else:
                print("Please enter a valid choice")
        elif choice == "2":
            print("Please choose if you want to decrypt a file or a folder")
            print("1. File")
            print("2. Folder")
            choice = input()
            if choice == "1":
                root = tk.Tk()
                root.withdraw()
                file_path = filedialog.askopenfilename()
                os.chdir(os.path.dirname(file_path))
                # Find extension file that ends with json
                extension_json = [f for f in os.listdir(os.getcwd()) if f.endswith(".json")]
                if len(extension_json) == 0:
                    print("No file with .json extension found,original extension cannot be recovered")
                    print("Press 3 to exit, press 2 to return to main menu")
                    choice = input()
                    if choice == "3":
                        flag = False
                    elif choice == "2":
                        flag = True
                else:
                    # Find extension file that ends with json
                    os.chdir(file_path)
                    extension_json = [f for f in os.listdir(os.getcwd()) if f.endswith(".json")]
                    with open(extension_json[0], "r") as f:
                        extension_json = json.loads(f.read())
                    # Remove extension on file_path
                    # Search file_path in extension_json for extension
                    for i in range(len(extension_json)):
                        if file_path in extension_json[0][i]:
                            extension = extension_json[0][i][file_path]
                            # Change file extension with new extension
                            change_file_extension(file_path, extension)
                            # Delete .AAAAA from end of the file_path
                            file_path = file_path[:-5]
                            # Add extension to file_path
                            file_path = file_path + extension
                            # Decrypt file
                            decrypt_txt_file(file_path)
                            os.remove(extension_json[0])
                    print("Decryption complete")
                    print("Press 3 to exit, press 2 to return to main menu")
                    choice = input()
                    if choice == "3":
                        flag = False
                    elif choice == "2":
                        flag = True
            elif choice == "2":
                print("Do you want subdirectories too or no?, just press 1 for yes or 2")
                choice = int(input())
                if choice == 1:
                    root = tk.Tk()
                    root.withdraw()
                    folder_path = filedialog.askdirectory()
                    subfolders = [f.path for f in os.scandir(folder_path) if f.is_dir()]
                    for subfolder in subfolders:
                        # Get basename of subfolder
                        basename = os.path.basename(subfolder)
                        extension_json = basename + "_ext.json"
                        # Find files in subfolder
                        files = [f.path for f in os.scandir(subfolder) if f.is_file()]
                        for file in files:
                            os.chdir(subfolder)
                            if len(extension_json) == 0:
                                print("No file with .json extension found,original extension cannot be recovered")
                                print("Press 3 to exit, press 2 to return to main menu")
                                choice = input()
                                if choice == "3":
                                    flag = False
                                elif choice == "2":
                                    flag = True
                            else:
                                os.chdir(subfolder)
                                #  Find extension file that ends with json
                                with open(extension_json, "r") as f:
                                    extension_json_data = json.loads(f.read())
                                # Search file_path in extension_json for extension
                                for i in range(len(extension_json_data)):
                                    if file in extension_json_data[i][0]:
                                        extension = extension_json_data[i][0][file]
                                        # Change file extension with new extension
                                        change_file_extension(file, extension)
                                        # Delete .AAAAA from end of the file_path
                                        file = file[:-5]
                                        # Add extension to file_path
                                        file = file + extension
                                        # Decrypt file
                                        decrypt_txt_file(file)
                        os.remove(extension_json)
                    basename = os.path.basename(folder_path)
                    extension_json = basename + "_ext.json"
                    os.chdir(folder_path)
                    # Scan files in folder_path
                    files = [f.path for f in os.scandir(folder_path) if f.is_file()]
                    for file in files:
                        if os.access(file, os.W_OK) and os.access(file, os.R_OK):
                            if len(extension_json) == 0:
                                print("No file with .json extension found,original extension cannot be recovered")
                                print("Press 3 to exit, press 2 to return to main menu")
                                choice = input()
                                if choice == "3":
                                    flag = False
                                elif choice == "2":
                                    flag = True
                            else:
                                os.chdir(subfolder)
                                #  Find extension file that ends with json
                                with open(extension_json, "r") as f:
                                    extension_json_data = json.loads(f.read())
                                # Search file_path in extension_json for extension
                                for i in range(len(extension_json_data)):
                                    if file in extension_json_data[i][0]:
                                        extension = extension_json_data[i][0][file]
                                        # Change file extension with new extension
                                        change_file_extension(file, extension)
                                        # Delete .AAAAA from end of the file_path
                                        file = file[:-5]
                                        # Add extension to file_path
                                        file = file + extension
                                        # Decrypt file
                                        decrypt_txt_file(file)
                        else:
                            pass
                    os.remove(extension_json)
                    print("Decryption complete")
                    print("Press 3 to exit, press 2 to return to main menu")
                    choice = input()
                    if choice == "3":
                        flag = False
                    elif choice == "2":
                        flag = True
                elif choice == 2:
                    root = tk.Tk()
                    root.withdraw()
                    folder_path = filedialog.askdirectory()
                    # Iterate through every file on folder_path with scandir
                    # Scan files in folder_path
                    files = [f.path for f in os.scandir(folder_path) if f.is_file()]
                    # Find extension file that ends with json
                    extension_jsonify = [f for f in os.listdir(folder_path) if f.endswith(".json")]
                    if len(extension_jsonify) == 0:
                        print("No file with .json extension found,original extension cannot be recovered")
                        print("Press 3 to exit, press 2 to return to main menu")
                        choice = input()
                        if choice == "3":
                            flag = False
                        elif choice == "2":
                            flag = True
                    for file in files:
                        os.chdir(folder_path)
                        #  Find extension file that ends with json
                        with open(extension_jsonify[0], "r") as f:
                            extension_json = json.loads(f.read())
                        # Search file_path in extension_json for extension
                        for i in range(len(extension_json)):
                            if file in extension_json[i][0]:
                                extension = extension_json[i][0][file]
                                # Change file extension with new extension
                                change_file_extension(file, extension)
                                # Delete .AAAAA from end of the file_path
                                file_path = file[:-5]
                                # Add extension to file_path
                                file_path = file_path + extension
                                # Decrypt file
                                decrypt_txt_file(file_path)
                    os.remove(extension_jsonify[0])
                    print("Decryption complete")
                    # Delete extension file
                    print("Press 3 to exit, press 2 to return to main menu")
                    choice = input()
                    if choice == "3":
                        flag = False
                    elif choice == "2":
                        flag = True
            else:
                print("Please enter a valid choice")
        elif choice == "3":
            flag = False
            sys.exit()
