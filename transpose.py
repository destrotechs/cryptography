class Transpose:
    alpha='a'
    orig_alphabets=[]
    
    key=""
    
    key_error=""
    templist1=[]
    templist2=[]
    

    
    def __init__(self):
        self.enc_alphabets=[]
        self.encryption_alphas=[]
        self.key_alphas=[]
        self.encrypted_message=[]
        for i in range(0,26):
            self.orig_alphabets.append(self.alpha)
            self.alpha=chr(ord(self.alpha)+1)

    def encrypt(self,message,key):
        self.key = key
        
        message=message.lower().replace(" ","")
        print(message)
        for i in list(self.key):
            self.enc_alphabets.append(i)
            self.orig_alphabets.remove(i)
        for j in list(self.orig_alphabets):
            self.enc_alphabets.append(j)
        print(self.enc_alphabets)
        #create two lists of the enc_alphabets

        for i in range(0,13):
            self.templist1.append(self.enc_alphabets[i])
        for j in range(13,26):
            self.templist2.append(self.enc_alphabets[j])

        #reverse templist2 elements to suit the algorithm
        self.templist2= [ele for ele in reversed(self.templist2)]
        
        # self.encryption_alphas.append(self.templist1)
        # self.encryption_alphas.append(self.templist2)

        
        message=list(message)

        for letter in message:
            index=self.enc_alphabets.index(letter)
            if(index>=13):
                letter_index=self.templist2.index(letter)
                self.encrypted_message.append(self.templist1[letter_index])
            else:
                letter_index=self.templist1.index(letter)
                self.encrypted_message.append(self.templist2[letter_index])
        # print(self.en)
        print(f"Plain Text : {' '.join(map(str, message))}")
        print(f"Cipher Text : {' '.join(map(str, self.encrypted_message))}")
        self.encrypted_message = ' '.join(map(str, self.encrypted_message))
         
    def enc_message(self):
        return self.encrypted_message
    def decrypt(self,message,key):
        self.key = key
        message=message.lower().replace(" ","")
        for i in list(self.key):
            self.enc_alphabets.append(i)
            self.orig_alphabets.remove(i)
        for j in list(self.orig_alphabets):
            self.enc_alphabets.append(j)
        
        #create two lists of the enc_alphabets

        for i in range(0,13):
            self.templist1.append(self.enc_alphabets[i])
        for j in range(13,26):
            self.templist2.append(self.enc_alphabets[j])

        #reverse templist2 elements to suit the algorithm
        self.templist2= [ele for ele in reversed(self.templist2)]
        
        # self.encryption_alphas.append(self.templist1)
        # self.encryption_alphas.append(self.templist2)

        
        message=list(message)

        for letter in message:
            index=self.enc_alphabets.index(letter)
            if(index>=13):
                letter_index=self.templist2.index(letter)
                self.encrypted_message.append(self.templist1[letter_index])
            else:
                letter_index=self.templist1.index(letter)
                self.encrypted_message.append(self.templist2[letter_index])

        # print(self.en)
        print(f"Cipher Text {' '.join(map(str, message))}")
        print(f"Plain Text {' '.join(map(str, self.encrypted_message))}")
        self.decrypted_message = ''.join(map(str, self.encrypted_message))

        return self.decrypted_message
