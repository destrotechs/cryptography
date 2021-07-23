from transpose import Transpose
import binascii
class Decrypt:
    hidden_key = "hidenq"
    scrumbled_key = "delbmurcs"
    cipher_binary_list=[]
    msg_bck = []

    def __init__(self,ciphertext,key):
        self.ciphertext = ciphertext.replace(" ","")
        self.key = key
        self.key_binary = bin(int.from_bytes(key.encode(), 'big'))[2:]
        self.scrumbled_key_bin = bin(int.from_bytes(self.scrumbled_key.encode(), 'big'))[2:]
        self.hidden_key_binary = bin(int.from_bytes(self.hidden_key.encode(), 'big'))[2:]


        self.cipher_to_binary(self.ciphertext)
    def cipher_to_binary(self,ciphertext):
        for i in ciphertext:
            temp_bin = format(ord(i), '08b')
            self.cipher_binary_list.append(temp_bin)
        print("Cipher Binary List: "+str(self.cipher_binary_list))





if __name__ == "__main__":
    message = "↨[gw?↨g{♠'g↨fg▬6"
    dec = Decrypt(message,"password")