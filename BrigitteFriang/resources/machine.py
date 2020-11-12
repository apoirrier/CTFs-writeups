from pyfinite import ffield, genericmatrix


def permutation15(a):
    b = "".join([a[7], a[3], a[13], a[8], a[12], a[10], a[2], a[5], a[0], a[14], a[11], a[9], a[1], a[4], a[6]])
    return b

def reverse_permutation15(a):
    b = "".join([a[8], a[12], a[6], a[1], a[13], a[7], a[14], a[0], a[3], a[11], a[5], a[10], a[4], a[2], a[9]])
    return b

def permutation(a):
    b0 = permutation15(a[15:30])
    b1 = permutation15(a[30:45])
    b2 = permutation15(a[0:15])
    return b0 + b1 + b2

def reverse_permutation(a):
    b0 = reverse_permutation15(a[30:])
    b1 = reverse_permutation15(a[:15])
    b2 = reverse_permutation15(a[15:30])
    return b0 + b1 + b2

def bin_format(x, n):
    return format(x, "0{}b".format(n))[::-1]

def toInt(x):
    return int(x[::-1], 2)

def xor(a, b):
    assert(len(a) == len(b))
    return "".join(["0" if a[i] == b[i] else "1" for i in range(len(a))])

""" Finite field operations """
GF = ffield.FField(5)
XOR = lambda x,y: x^y
MUL = lambda x,y: GF.Multiply(x,y)
DIV = lambda x,y: GF.Multiply(x, GF.Inverse(y))
m = genericmatrix.GenericMatrix(size=(3,3),zeroElement=0,identityElement=1,add=XOR,mul=MUL,sub=XOR,div=DIV)
alpha = 2
m.SetRow(0,[1,1,alpha])
m.SetRow(1,[1,alpha,1])
m.SetRow(2,[alpha,1,1])

def round(data, key):
    tmp = permutation(data)
    tmp2 = ""
    for i in range(0, 45, 5):
        x = toInt(tmp[i:i+5])
        tmp2 += bin_format(GF.Inverse(x), 5)
    tmp = xor(tmp2, key)
    tmp2 = ""
    for i in range(0,45,15):
        x = [toInt(tmp[i+j:i+j+5]) for j in range(0,15,5)]
        y = m.LeftMulColumnVec(x)
        for j in range(3):
            tmp2 += bin_format(y[j], 5)
    return tmp2

def reverse_round(data, key):
    tmp = ""
    for i in range(0,45,15):
        y = [toInt(data[i+j:i+j+5]) for j in range(0,15,5)]
        x = m.Solve(y)
        for j in range(3):
            tmp += bin_format(x[j], 5)
    tmp2 = xor(tmp, key)
    tmp = ""
    for i in range(0, 45, 5):
        x = toInt(tmp2[i:i+5])
        tmp += bin_format(GF.Inverse(x), 5)
    tmp2 = reverse_permutation(tmp)
    return tmp2

def key_expansion(key):
    reg = list(key)
    tmp = reg[63]
    for i in range(63, 0, -1):
        reg[i] = reg[i-1]
    reg[0] = tmp
    reg[9] = xor(reg[9], tmp)
    reg[34] = xor(reg[34], tmp)
    reg[61] = xor(reg[61], tmp)
    return "".join(reg)

KEY = bin_format(0x4447534553494545, 64)

def encrypt_block(data):
    data = data[::-1]
    key = KEY
    data = xor(data, key[:45])
    key = key_expansion(key)
    for i in range(5):
        data = round(data, key[:45])
        key = key_expansion(key)
    data = data[::-1]
    return data


def decrypt_block(data):
    data = data[::-1]
    key = KEY
    keys = [KEY]
    for i in range(5):
        key = key_expansion(key)
        keys.append(key)
    for i in range(5,0,-1):
        data = reverse_round(data, keys[i][:45])
    data = xor(data, keys[0][:45])
    
    data = data[::-1]
    return data

if __name__ == "__main__":
    PTXT = "011001010111011001101001011011000000000000000"
    CTXT = "000101110010110001110101010111010101001010100"

    if(encrypt_block(PTXT) == CTXT):
        print("Encryption correct")

    if(decrypt_block(CTXT) == PTXT):
        print("Decryption correct")

    ctxt = "010111101111101000100001111000001001100111111101111010000011100111100000101100010101000110100000000011101101111110010100111111101100110001110100110101101111100111001011110110100011101100111001000111101110101010110111011110010100010000011111101011101110101111110100111011110100100100111001010001010101001011001010100110101000010110000000101101100000101000011000101111110100111100000100110101001010100110011111011101001110110010011100011000100110000011"
    ptxt = ""
    for i in range(0,len(ctxt), 45):
        ptxt += decrypt_block(ctxt[i:i+45])
    print(ptxt)

# https://www.edaplayground.com/x/jwaU?fbclid=IwAR0hGgw3vz0J7pJPKdKcJTro_LwAB90JOT34QSQgkKysnG1lEP8X86BvdjU
# DGSESIEE{666bcd546262034826578452ffa448763b31010146999}