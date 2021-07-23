"""
        =======morris mbae==========================
        encryption class, plaintext manipulation is done here
        the end product is an encrypted string(ciphertext) that can be 
        shared for confidentiality.
        ====================algo flow================
        1. receive message and key from encryptor(sender)
        2. encrypt the message using transposition classical algorithm
        3. Hidden key is "HidenQ" 
        4. convert the result into binary(message and key) separetely
        5. concatenate the message binary and key binary
        6. split the result binarytext into two chunks
        7. XOR each chunk with Hidden key followed by real key respectively
        8. reverse chunk 1 and shift chunk 2
        9. concatenate chunk 1 and chunk 2
        10. convert output to string and output the resulting string
"""
from transpose import Transpose

class Encrypt:
    hidden_key = "hidenq"
    scrumbled_key = "delbmurcs"
    def __init__(self, plaintext,key,in_type):
        self.plaintext = plaintext
        self.key = key
        if(in_type=='text'):
        
            self.transposeMessage()
        elif(in_type =='file'):
            self.convert_to_string(self.plaintext,self.key)
        else:
            pass
    def transposeMessage(self):

        transpose_plain_text =  Transpose()

        
        transpose_plain_text.encrypt(self.plaintext,self.hidden_key)
        self.transposed_plaintext = transpose_plain_text.enc_message()
        print("Transposed plain Text: ",self.transposed_plaintext)

        #convert the strings to binary
        self.convert_to_string(self.transposed_plaintext,self.key)
    def convert_to_string(self,tplaintext,key):
        self.plaintext_binary = ''.join(format(ord(i), '08b') for i in tplaintext)
        #  bin(int.from_bytes(tplaintext.encode(), 'big'))[2:]
        self.key_binary = ''.join(format(ord(i), '08b') for i in key)
        # bin(int.from_bytes(key.encode(), 'big'))[2:]
        self.scrumbled_key_bin = ''.join(format(ord(i), '08b') for i in self.scrumbled_key)
        # bin(int.from_bytes(self.scrumbled_key.encode(), 'big'))[2:]
        self.hidden_key_binary = ''.join(format(ord(i), '08b') for i in self.hidden_key)
        # bin(int.from_bytes(self.hidden_key.encode(), 'big'))[2:]

        # print("PlainText Binary: "+self.plaintext_binary)
        # print("Key Binary: "+self.key_binary)
    
        self.concatenate_btext_bkey(self.plaintext_binary,self.key_binary)

    def concatenate_btext_bkey(self,bptext,bkey):
        self.orig_b_key_length = len(bkey)
        self.orig_b_ptext_length = len(bptext)

        self.concatenated_binary_string = bptext+self.scrumbled_key_bin

        # print("Concatenated Binary Plaintext and KeyBinary: "+self.concatenated_binary_string)   
        # print("Scrambled  Binary key Length : "+str(len(self.scrumbled_key_bin)))
        # print("Original Binary PlaintText Length: "+str(self.orig_b_ptext_length))

        self.split(self.concatenated_binary_string)
    def split(self,concatenated_string):
        str_length = len(concatenated_string)
        # print("Length of concat string before zfill : "+str(str_length))
        if(str_length%2)!=0:
            concatenated_string = concatenated_string.zfill(len(concatenated_string)+1)
            str_length = len(concatenated_string)
        half_length = int(str_length/2)
        
        # print("Zfilled binary string : "+concatenated_string)
        self.chunk1 = concatenated_string[:half_length]
        self.chunk2 = concatenated_string[half_length:]

        # print("Chunk 1: "+self.chunk1+" Length: "+str(len(self.chunk1)))
        # print("Chunk 2: "+self.chunk2+" Length: "+str(len(self.chunk2)))

        self.XOR_chunk1(self.chunk1,half_length)

        self.XOR_chunk2(self.chunk2,half_length)
    def XOR_chunk1(self,chunk1,chunk1_length):
        # print("================CHUNK 1==================")
        # print("Original SBinary Key : "+self.hidden_key_binary)
        # print("Length of SKey binary : "+str(len(self.hidden_key_binary)))
        # print("Chunk 1 Length : "+str(chunk1_length))
        
        #check length against the hiddenkey
        if(chunk1_length>len(self.hidden_key_binary)):
            while (chunk1_length - len(self.hidden_key_binary)) > 0:
                self.hidden_key_binary += self.hidden_key_binary
                if (len(self.hidden_key_binary) > chunk1_length):
                    self.hidden_key_binary = self.hidden_key_binary[:chunk1_length]
                    break
        elif(chunk1_length<len(self.hidden_key_binary)):
            diff = len(self.hidden_key_binary)-chunk1_length
            self.chunk1 = chunk1.zfill(len(self.hidden_key_binary)+diff)
        else:
            pass
        
        # print("Length of Key Binary after padding : "+str(len(self.hidden_key_binary)))
        # print("Chunk 1 bin : "+chunk1)
        # print("New Pad Key : "+self.hidden_key_binary)
        #XOR with first key
        
        self.xored1_chunk1 = '{1:0{0}b}'.format(len(chunk1), int(chunk1, 2) ^ int(self.hidden_key_binary, 2))

        # print("Xd wt hKey 1 : "+self.xored1_chunk1)

        
        #check length against real key

        # print("User Key orig : "+self.key_binary+" Length: "+str(len(self.key_binary)))
        
        if(len(self.xored1_chunk1)>len(self.key_binary)):
            while (len(self.xored1_chunk1) - len(self.key_binary)) > 0:
                self.key_binary += self.key_binary
                if (len(self.key_binary) > len(self.xored1_chunk1)):
                    self.key_binary = self.key_binary[:len(self.xored1_chunk1)]
                    break
        elif(chunk1_length<len(self.key_binary)):
            diff = len(self.key_binary)-len(self.xored1_chunk1)
            self.xored1_chunk1 = self.xored1_chunk1.zfill(len(self.key_binary)+diff)
        else:
            pass
        
        # print("Orig User key after padd: "+self.key_binary+" Length: "+str(len(self.key_binary)))
        

        self.xored2_chunk1 = '{1:0{0}b}'.format(len(self.xored1_chunk1), int(self.xored1_chunk1, 2) ^ int(self.key_binary, 2))

        # print("Padded Key Bin : "+self.key_binary)
        # print("Xored with Orig Key: "+self.xored2_chunk1)
        
        self.reverseChunk1(self.xored2_chunk1,len(self.xored2_chunk1))

    def reverseChunk1(self,xored_chunk1,xored_chunk1_length):
        self.reversed_xored_chunk1 = xored_chunk1[xored_chunk1_length - 1::-1]
        # print("Reversed chunk 1: " + self.reversed_xored_chunk1)
        # print("====================END OF CHUNK 1================")

        # return False
    def XOR_chunk2(self,chunk2,chunk2_length):
        # print("=======CHUNK2========")
        # print("Length of Key binary : "+str(len(self.hidden_key_binary)))

        #check length against the hiddenkey
        if(chunk2_length>len(self.hidden_key_binary)):
            while (chunk2_length - len(self.hidden_key_binary)) > 0:
                self.hidden_key_binary += self.hidden_key_binary
                if (len(self.hidden_key_binary) > chunk2_length):
                    self.hidden_key_binary = self.hidden_key_binary[:chunk2_length]
                    break
        elif(chunk2_length<len(self.hidden_key_binary)):
            diff = len(self.hidden_key_binary)-chunk2_length
            self.chunk2 = chunk2.zfill(len(self.hidden_key_binary)+diff)
        else:
            pass
        
        # print("Length of Key Binary after padding : "+str(len(self.hidden_key_binary)))
        # print("Chunk 2 bin : "+chunk2)
        # print("New Pd key  : "+self.hidden_key_binary)
        #XOR with first key
        
        self.xored1_chunk2 = '{1:0{0}b}'.format(len(chunk2), int(chunk2, 2) ^ int(self.hidden_key_binary, 2))

        # print("Xrd wt hKey 1 : "+self.xored1_chunk2)
        
        #check length against real key
        if(len(self.xored1_chunk2)>len(self.key_binary)):
            while (len(self.xored1_chunk2) - len(self.key_binary)) > 0:
                self.key_binary += self.key_binary
                if (len(self.key_binary) > len(self.xored1_chunk2)):
                    self.key_binary = self.key_binary[:len(self.xored1_chunk2)]
                    break
        elif(chunk2_length<len(self.key_binary)):
            diff = len(self.key_binary)-len(self.xored1_chunk2)
            self.xored1_chunk2 = self.xored1_chunk2.zfill(len(self.key_binary)+diff)
        else:
            pass
        # print("Orig B Key: "+self.key_binary+" Length: "+str(len(self.key_binary)))
        
        self.xored2_chunk2 = '{1:0{0}b}'.format(len(self.xored1_chunk2), int(self.xored1_chunk2, 2) ^ int(self.key_binary, 2))
        # print("Xored1 Bin     : "+self.xored1_chunk2)
        # print("Padded Key Bin : "+self.key_binary)
        # print("Xd wt  Orig Key: "+self.xored2_chunk2)
        
    #shift the new xored chunk 2

        self.shift(self.xored2_chunk2)
    
    def shift(self,xored_chunk2):
        self.shifted_xored_chunk2 = (xored_chunk2[5:] + xored_chunk2[:5])
        # print("Shifted Xored chunk 2: "+ self.shifted_xored_chunk2)
        #concatenate the reversed and shifted binaries
        
        self.concatenate_final_binaries(self.reversed_xored_chunk1,self.shifted_xored_chunk2)
    
    def concatenate_final_binaries(self,xrchunk1,xschunk2):
        self.final_binary_string = xrchunk1+xschunk2

        # print("Final Encrypted Binary String : "+self.final_binary_string + " Length: "+str(len(self.final_binary_string)))
        
        
        return self.final_binary_string
        #final encrypted strin
        # self.final_enc_to_string(self.final_binary_string)

    def final_enc_to_string(self,final_bin):
        str_data = ""
        for i in range(0, len(final_bin), 8):
            temp_data = final_bin[i:i + 7]
            decimal_data = self.BinaryToDecimal(temp_data)
            str_data = str_data + chr(decimal_data)
        # print("Cipher Text : '" + str_data.lower()+"'")
        str_data = str_data.replace(" ","")
        # print("FinBi Bin back : "+self.final_binary_string)

        # print("Check Bin back : "+bin(int.from_bytes(str_data.encode("utf-8"), 'big'))[2:])
    def get_encrypted_bin(self):
        return self.final_binary_string
    def BinaryToDecimal(self, binary):
        string = int(binary, 2)
        return string



if __name__ == "__main__":    
    pass
    # print(text)

    
