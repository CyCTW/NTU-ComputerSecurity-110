import hashlib
ans = '12f3b9faec781b0e84184a6fa7c44c81416e5b1855633a2a2730295324724efe'

lines = []
with open('transcript.txt') as f:
  lines = f.readlines()

for line in lines:
  words = line.split()
  for word in words:
    s = hashlib.sha256()
    # print(data)
    s.update('salt'.encode())
    s.update(word.encode())
    h = s.hexdigest()
    if h == ans:
      print("FIND!", word)
      break
    # print(h)
    # break
  

