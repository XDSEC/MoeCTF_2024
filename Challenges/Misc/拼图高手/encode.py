from base64 import b64encode as be
def self_encoding(input_text):
    code_setting_first="doanythigfruebcjklmqpswvxz"
    code_setting_sec="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    number_setting = "0123456789"
    encoded_text=" "
    for x in input_text:
        if x in code_setting_first:
            if ord(x) < 104 :
                num = ord(x) + 19
            elif ord(x) > 115:
                num = ord(x) - 19
            elif 104 <= ord(x) <= 115:
                num = 219 - ord(x)
            encoded_text += chr(num) + " "        

        elif x in code_setting_sec:
            if 64 < ord(x) < 72:
                num = ord(x) + 7  
            elif 71 < ord(x) < 79:
                num = ord (x) - 7 
            elif 78 < ord(x) < 82:
                num = ord(x) + 9 
            elif 87 < ord(x) < 91:
                num = ord(x) - 9 
            elif 81 < ord(x) < 88:
                num = 168 - ord(x) 
            encoded_text += chr(num) + " "
        
        elif x not in number_setting:
            encoded_text += x

    for i in range(len(input_text)):
        if input_text[i] in number_setting:
            if i != len(input_text) -1:
                x = int(input_text[i]) ^ int(input_text[i+1])
                encoded_text += str(x) + " "
            elif i == len(input_text) - 1:
                encoded_text += input_text[-1]
    return encoded_text

def reverse_encoding(input_text):
    output_text = input_text[::-1]
    return output_text

def strange_character_hint(key):
    key = self_encoding(reverse_encoding(key))
    res="".join((key).split(" "))
    print(be(res.encode('utf-8')))

"""enjoy the revenge!"""

if __name__=="__main__":
    input_text = "idon'tknow"
    key="don'tknoweither"
    print("".join((reverse_encoding(self_encoding(input_text))).split(" ")))
    strange_character_hint(key)


    #strange_character_hint(key)$output:b'eGl4c2R4bmxVbVhpeHVuYkdzYXJkZnRhVWl4YXZ0aXRzSnh6bXRpYVU='