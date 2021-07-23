from transpose import Transpose
import binascii
class Decrypt:
    hidden_key = "hidenq"
    scrumbled_key = "delbmurcs"

    def __init__(self,ciphertext,key,type):
        self.filetype=type
        self.ciphertext = ciphertext.replace(" ","")
        self.key = key
        self.orig_s_key_bin=bin(int.from_bytes(self.scrumbled_key.encode(), 'big'))[2:]
        self.key_binary = ''.join(format(ord(i), '08b') for i in key)
        self.scrumbled_key_bin = bin(int.from_bytes(self.scrumbled_key.encode(), 'big'))[2:]
        self.hidden_key_binary = ''.join(format(ord(i), '08b') for i in self.hidden_key)

        # print("Ciphertext received : "+self.ciphertext)
        
        self.cipher_to_binary(self.ciphertext)

    def cipher_to_binary(self,ciphertext):       
        
        self.cipher_binary = ciphertext
        #"101101101010011000010110101111101010111000001110010101101111011011010110110011101000111000000110010011000110110000101111000011001100111001001111000011111010111110001111000011111110111101101110"
        # ''.join(format(ord(c), 'b') for c in self.ciphertext)
        # "101101101010011000010110101111101010111000001110010101101111011011010110110011101000111000000110010011000110110000101111000011001100111001001111000011111010111110001111000011111110111101101110"
        # ' '.join(format(ord(c), 'b') for c in self.ciphertext)
        # ''.join(format(x, 'b') for x in bytearray(self.ciphertext, 'utf-8'))
        # bin(int.from_bytes(self.ciphertext.encode("utf-8"), 'big'))[2:]

        print("Check Bin back : "+self.cipher_binary[:20]+" Length :"+str(len(self.cipher_binary)))

        # self.final_dec_to_string(self.cipher_binary)
       
        self.split()

    def split(self):
        # cipher_length = len(self.cipher_binary)
        # print(cipher_length)
        
        # if(cipher_length%2)!=0:
        #     self.cipher_binary = self.cipher_binary.zfill(cipher_length+1)
        
        # print("Cipher text binary after padding : "+self.cipher_binary)

        half_length = int(len(self.cipher_binary)/2)

        
        
        self.chunk1 = self.cipher_binary[:half_length]

        self.chunk2 = self.cipher_binary[half_length:]

        print("Chunk 1 : "+self.chunk1[:20])
        # return False
        print("Chunk 2 : "+self.chunk2[:20])
        
        #reverse chunk1
        self.reverse_chunk1(self.chunk1,half_length)
       
        #shiftback chunk2
        # self.shift_back_chunk2(self.chunk2)

    def reverse_chunk1(self,chunk1,chunk1_length):
        self.reversed_chunk1 = chunk1[chunk1_length - 1::-1]

        print("Reversed chunk1 : "+self.reversed_chunk1[:20])
        
        self.XOR_chunk1(self.reverse_chunk1,chunk1_length)

    def shift_back_chunk2(self,chunk2):
        self.shifted_chunk2 = (chunk2[-5:] + chunk2[:-5])
        print("shifted chunk 2 (original): ", self.shifted_chunk2[:20])
        length = len(chunk2)
        
        self.XOR_chunk2(self.shifted_chunk2,length)
    
    def XOR_chunk1(self,chunk1,chunk1_length):
        #xor with real key
        if(chunk1_length > len(self.key_binary)):
            while (chunk1_length - len(self.key_binary)) > 0:
                self.key_binary += self.key_binary
                if (len(self.key_binary) > chunk1_length):
                    self.key_binary = self.key_binary[:chunk1_length]
                    break
        elif(chunk1_length<len(self.key_binary)):
            diff = len(self.key_binary)-len(chunk1)
            chunk1 = chunk1.zfill(len(self.key_binary)+diff)
        else:
            pass
        print("Chunk 1         : "+self.chunk1[:20])
        print("Padded orig key : "+self.key_binary[:20])
        
        self.xored1_chunk1 = '{1:0{0}b}'.format(len(self.reversed_chunk1), int(self.reversed_chunk1.replace(" ",""), 2) ^ int(self.key_binary.replace(" ",""), 2))
        
        print("Xored with Orig Key: "+self.xored1_chunk1[:20])
        
        # return False
        #xor with hidden key
        if(len(self.xored1_chunk1)>len(self.hidden_key_binary)):
            while (len(self.xored1_chunk1) - len(self.hidden_key_binary)) > 0:
                self.hidden_key_binary += self.hidden_key_binary
                if (len(self.hidden_key_binary) > len(self.xored1_chunk1)):
                    self.hidden_key_binary = self.hidden_key_binary[:len(self.xored1_chunk1)]
                    break
        elif(len(self.xored1_chunk1)<len(self.hidden_key_binary)):
            diff = len(self.hidden_key_binary)-len(self.xored1_chunk1)
            chunk1 = chunk1.zfill(len(self.hidden_key_binary)+diff)
        else:
            pass

        print("New Padded Key: "+self.hidden_key_binary[:20])

        self.xored2_chunk1 = '{1:0{0}b}'.format(len(self.xored1_chunk1), int(self.xored1_chunk1, 2) ^ int(self.hidden_key_binary, 2))

        print("Xored with Hidden key: "+self.xored2_chunk1[:20])
        
        self.chunk1 = self.xored2_chunk1

        self.shift_back_chunk2(self.chunk2)
    def XOR_chunk2(self,chunk2,chunk2_length):
        #xor with real key
        if(len(chunk2)>len(self.key_binary)):
            while (len(chunk2) - len(self.key_binary)) > 0:
                self.key_binary += self.key_binary
                if (len(self.key_binary) > len(chunk2)):
                    self.key_binary = self.key_binary[:len(chunk2)]
                    break
        elif(chunk2_length<len(self.key_binary)):
            diff = len(self.key_binary)-len(chunk2)
            chunk2 = chunk2.zfill(len(self.key_binary)+diff)
        else:
            pass

        self.xored1_chunk2 = '{1:0{0}b}'.format(len(chunk2), int(chunk2.replace(" ",""), 2) ^ int(self.key_binary.replace(" ",""), 2))

        print("Xored with Orig Key: "+self.xored1_chunk2[:20])
        
        #xor with hidden key
        if(len(self.xored1_chunk2)>len(self.hidden_key_binary)):
            while (len(self.xored1_chunk2) - len(self.hidden_key_binary)) > 0:
                self.hidden_key_binary += self.hidden_key_binary
                if (len(self.hidden_key_binary) > len(self.xored1_chunk2)):
                    self.hidden_key_binary = self.hidden_key_binary[:len(self.xored1_chunk2)]
                    break
        elif(len(self.xored1_chunk2)<len(self.hidden_key_binary)):
            diff = len(self.hidden_key_binary)-len(self.xored1_chunk2)
            chunk2 = chunk2.zfill(len(self.hidden_key_binary)+diff)
        else:
            pass

        print("New Padded Key: "+self.hidden_key_binary[:20])

        self.xored2_chunk2 = '{1:0{0}b}'.format(len(self.xored1_chunk2), int(self.xored1_chunk2, 2) ^ int(self.hidden_key_binary, 2))
        
        print("Xored with hidden key : "+self.xored2_chunk2[:20])
        
        self.chunk2 = self.xored2_chunk2

        self.concatenate_back(self.chunk1,self.chunk2)

    def concatenate_back(self,chunk1,chunk2):
        self.plaintext_bin=chunk1+chunk2

        print("Original Bin ch1+ch2 "+self.plaintext_bin[:20])
        
        print("Orig S Key: "+self.orig_s_key_bin[:20])
        # self.orig_scrumbled_key_bin = ''.join(format(ord(i), '08b') for i in self.scrumbled_key)
        message_size = len(self.plaintext_bin)-len(self.orig_s_key_bin)

        self.final_plaintext_bin = self.plaintext_bin[:message_size]

        print("Final Plaintext Binary : "+self.final_plaintext_bin[:20])
        
        self.final_dec_to_string(self.final_plaintext_bin[1:])
        
    def final_dec_to_string(self,final_bin):
        str_data = ' '
        for i in range(0, len(final_bin), 8):
            temp_data = final_bin[i:i + 7]
            decimal_data = self.BinaryToDecimal(temp_data)
            str_data = str_data + chr(decimal_data)
        
        print("Final Transposed String : "+str_data[:20])
        if self.filetype !="file":
            self.transpose_Back(str_data)
        else:
            self.origmessage =str_data
    def BinaryToDecimal(self, binary):
        string = int(binary, 2)
        return string

    def transpose_Back(self,message):
        dec = Transpose()

        dec.encrypt(message,self.hidden_key)
        self.origmessage = dec.enc_message()
        
        print("Original Message : "+self.origmessage[:20])
        # self.final_dec_to_string(self.final_plaintext_bin[1:])

    def getDecryptedString(self):
        return self.origmessage.replace(" ","")













if __name__ == "__main__":
    pass
    message = "10011100001101000011010011010100110011001010110000110100110011001000011011100110101001111000010101000110001001110000010111000111"
    dec = Decrypt(message,"1234")