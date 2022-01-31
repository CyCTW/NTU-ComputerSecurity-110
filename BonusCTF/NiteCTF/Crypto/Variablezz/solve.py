from sage.all import *

Ciphertext = [8194393930139798, 7130326565974613, 9604891888210928, 6348662706560873, 11444688343062563, 7335285885849258, 3791814454530873, 926264016764633, 9604891888210928, 5286663580435343, 5801472714696338, 875157765441840, 926264016764633, 2406927753242613, 5980222734708251, 5286663580435343, 2822500611304865, 5626320567751485, 3660106045179536, 2309834531980460, 12010406743573553]
a, b, c, d = var('a, b, c, d')
y = Ciphertext[:4]
x = [ord('n'), ord('i'), ord('t'), ord('e')]

def f(idx):
  global a, b, c, d, x, y
  return y[idx] == (a*(x[idx]**3) + b*(x[idx]**2) + c*x[idx] + d)

ans = solve([ f(0), f(1), f(2), f(3)], a, b, c, d)
print(ans)
A = ans[0][0].rhs()
B = ans[0][1].rhs()
C = ans[0][2].rhs()
D = ans[0][3].rhs()

X = var('X')
plains = ""
for cipher in Ciphertext:
  # decrypt
  ans = solve([cipher == A*(X**3)+B*(X**2)+C*X+D], X)
  # print(ans[2].rhs())
  plains += chr(ans[2].rhs())
print(f"Flag: {plains}")


  