#Network Security
#Vigenere Encryption/Decryption Algorithms
#February 15, 2021



# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------




#1 Vigenere Encryption Function
def vigenere_enc (vig_key, vig_plaintext):

  original = vig_plaintext

  #Making my plaintext and key uppercase to correspond to ascii 65-90, and remove the spaces
  vig_plaintext = vig_plaintext.upper()
  vig_plaintext = vig_plaintext.replace(" ", "")
  vig_key = vig_key.upper()
  vig_key = vig_key.replace(" ", "")
  vigcipher = ""

  #Filling the character of the key if the length is different to the plaintext
  i = 1
  while len(vig_key) < len(vig_plaintext):
    vig_key = vig_key + vig_key[i-1]
    i += 1

  while len(vig_plaintext) < len(vig_key):
    vig_plaintext = vig_plaintext + vig_plaintext[i-1]
    i += 1

  vigcipher_temp = ""
  #The interesting part
  j = 0
  while j < len(vig_key):
    shift = ord(vig_key[j]) - 65 #Getting the key character in the mod26 range
    new_val = ord(vig_plaintext[j]) - 65 #Getting the plaintext character in the mod26 range
    update = (shift + new_val)%26   #Getting the cipher character in mod26
    vigcipher_temp = vigcipher_temp + chr(update + 65)
    j += 1                    #Go through the loop as long as we haven't reached the end of the string

  count=0
  while count < (len(original)-1):
    vigcipher += vigcipher_temp[count] + ""
    count += 1

  return vigcipher



# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------




#2 Vigenere Decryption Function
def vigenere_dec (vig_key2, vig_ciphtext):

  original2 = vig_ciphtext

  #Making my ciphertext and key uppercase to correspond to ascii 65-90, and remove the spaces
  vig_ciphtext = vig_ciphtext.upper()
  vig_ciphtext = vig_ciphtext.replace(" ", "")
  vig_key2 = vig_key2.upper()
  vig_key2 = vig_key2.replace(" ", "")
  vigplain = ""

  #Filling the character of the key if the length is different to the ciphertext
  k = 1
  while len(vig_key2) < len(vig_ciphtext):
    vig_key2 = vig_key2 + vig_key2[k-1]
    k += 1

  while len(vig_ciphtext) < len(vig_key2):
    vig_ciphtext = vig_ciphtext + vig_ciphtext[k-1]
    k += 1

  #The interesting part
  m = 0
  vigplain_temp = ""
  while m < len(vig_key2):
    shift2 = ord(vig_key2[m]) - 65 #Getting the key character in the mod26 range
    new_val2 = ord(vig_ciphtext[m]) - 65 #Getting the ciphertext character in the mod26 range
    update2 = (new_val2 - shift2)%26   #Getting the cipher character in mod26
    vigplain_temp = vigplain_temp + chr(update2 + 65)
    m += 1                    #Go through the loop as long as we haven't reached the end of the string


  count2=0
  while count2 <= (len(original2)-1):
    vigplain += vigplain_temp[count2]
    count2 += 1

  return vigplain



# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------



#Main code with testing
if __name__ == "__main__":
  ciph = vigenere_enc("KEY", "Test String")
  print("VIGENERE: For the plaintext \"Test String\" and the key \"KEY\", the encrypted text is", ciph)
  plain = vigenere_dec("KEY", ciph)
  print("VIGENERE: For the ciphertext", ciph, "and the key \"KEY\", the plaintext is", plain)
