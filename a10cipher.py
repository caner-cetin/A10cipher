import pydub
from playsound import playsound
from pydub import AudioSegment
import numpy as np
import sys
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
    playsound("Serious Sam Kamikaze scream.wav")



plaintext = "fuck... "
plaintext = plaintext.upper().replace(" ","")
key = "hill"
key = key.upper().replace(" ","")
ciphertext = hill_encryption(plaintext, key)
A10_decryption(ciphertext, key)
