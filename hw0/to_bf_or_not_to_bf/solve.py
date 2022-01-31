import cv2
import numpy as np

img1 = cv2.imread('flag_enc.png', cv2.IMREAD_GRAYSCALE)
img2 = cv2.imread('golem_enc.png', cv2.IMREAD_GRAYSCALE)

h, w = img1.shape
img3 = np.array([[0 for i in range(w)] for j in range(h)], np.uint8)

for i in range(h):
    for j in range(w):
        img3[i][j] = img1[i][j] ^ img2[i][j]
cv2.imwrite('dec.png', img3)
