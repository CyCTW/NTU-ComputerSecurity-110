random_sequence_1 = [219, 182, 109, 219, 182, 109, 219, 182, 109, 219]
random_sequence_2 = [182, 109, 219, 182, 109, 219, 182, 109, 219, 182]
random_sequence_3 = [109, 219, 182, 109, 219, 182, 109, 219, 182, 109]
random_sequence_4 = [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
import time
random_sequence = [random_sequence_1, random_sequence_2, random_sequence_3, random_sequence_4]

enc = int("9dfa2c9ccd5c84c61feb00ea835e848732ac8701da32b5865a84db59b08532b6cf32ebc10384c45903bf860084d018b5d55a5cebd832ef8059ead810", 16)
enc = enc.to_bytes(60, byteorder='big')
ans_idx = [0, 1, 1 ,2]
first_pattern = 0
last_pattern = 0

# Find first pattern
for idx, seq in enumerate(random_sequence):
    tmp = seq[0] ^ enc[0]
    # print(tmp)
    if tmp == ord('F'):
        # print("Find!")
        # print(idx)
        first_pattern = idx
        break

# Find last pattern
for idx, seq in enumerate(random_sequence):
    tmp = seq[9] ^ enc[59]
    if tmp == ord('}'):
        # print(idx)
        last_pattern = idx
        break

flag = ""

for i in range(4):
    for j in range(4):
        for k in range(4):
            for l in range(4):
                # total_seq = random_sequence[0] + random_sequence[i] + random_sequence[j] + random_sequence[k]+ random_sequence[l]+ random_sequence[2]
                flag = ""
                total_seq = []
                total_seq += random_sequence[first_pattern]
                for q in [i, j, k, l]:
                    total_seq += random_sequence[q]
                total_seq += random_sequence[last_pattern]
                # print(total_seq)
                # print(len(total_seq))
                for q in range(60):
                    tmp = enc[q] ^ total_seq[q]
                    flag += chr(tmp)
                print(flag)
                # time.sleep(10)

