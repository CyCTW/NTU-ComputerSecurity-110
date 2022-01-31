import random
enc = int("d5de8acdc0fa83d9c5bbe683cb33ef07949d6faeee8b00f6a2cc10cad800ca818e1cfd34f96f8fe71c9dbb3930ec8fb89183c9eef059cddcdc62a3fcf96eaea6dcab1bde96db8dbb13e3eb5d144fec9c6c91637cffdb0d8c988c2a189a8aaeaa136afe8cd469dddedf88ed7effbf2fd89e8f8afa88beb9ba1150eaaec0c8fdb5d4fbe3efff8ca866ecbf2bda996a7f9e136d6d6e1afbccb664e24d5ef98e9fa63e8d8b3a385aef999389d9dcfbe9f8f6d4908bdaf9bdbd8dfeaebafea28aca8c9181cb8ca8cbc9a6f48893dcf94b8b4efca91a8ab1a84f9893ac4fafb86ee9dbff7a9949ff6e8fe40a9daa2c30ea99b89383c9ecf459d8d8dc66a1fcff6daeb4caab0ad896c88cbb11e3eb4c134ff9886c84617cf9cf0d8b9d8c3b189a88adaa117dfe8ac369c8c9df88f87ef9ad2fce9f8f9be988a9adba1343eabbd6c8e8b4d4eaf2eff989a865febf3acb996c6d9e11696d6c1afbd9b664e64b5eff899fb42c8d9a383849ea99918dd9cdf8e9ede6d4858ddaffadbd8affaeabfaa288cd8c9392cb8abbcbdcb5f48882dcff5d8b58f9a90b9db1bf5f9891bb4fbaaa6efcdeff6b8c49", 16)
enc_bytes = enc.to_bytes(420, byteorder='big')

your_randoms = []
for i in range(36, 420):
    your_randoms.append(enc_bytes[i])

flags_random = []
for i in range(384-36, 384):
    flags_random.append(your_randoms[i])

flags = ""
for i in range(36):
    flags += chr(flags_random[i] ^ enc_bytes[i])
print(flags)

                


