import base64

flag = input("Input the flag format (case-sensitive, e.g. `flagCTF{`): ")
print()

decimal = [ord(c) for c in flag]
aux = [str(c) for c in decimal]
print('Decimal: {}'.format(' '.join(aux)))

hexadecimal = [hex(c) for c in decimal]
print('Hexadecimal: {}'.format(' '.join(hexadecimal)))

b = bytes(flag, 'utf-8')
base_64 = base64.b64encode(b)
print('Base64: {}'.format(base_64.decode()))

binary = [bin(c).replace('b', '') for c in decimal]
print('Binary: {}'.format(' '.join(binary)))

MORSE_CODE_DICT = { 'A':'.-', 'B':'-...', 
                    'C':'-.-.', 'D':'-..', 'E':'.', 
                    'F':'..-.', 'G':'--.', 'H':'....', 
                    'I':'..', 'J':'.---', 'K':'-.-', 
                    'L':'.-..', 'M':'--', 'N':'-.', 
                    'O':'---', 'P':'.--.', 'Q':'--.-', 
                    'R':'.-.', 'S':'...', 'T':'-', 
                    'U':'..-', 'V':'...-', 'W':'.--', 
                    'X':'-..-', 'Y':'-.--', 'Z':'--..', 
                    '1':'.----', '2':'..---', '3':'...--', 
                    '4':'....-', '5':'.....', '6':'-....', 
                    '7':'--...', '8':'---..', '9':'----.', 
                    '0':'-----', ', ':'--..--', '.':'.-.-.-', 
                    '?':'..--..', '/':'-..-.', '-':'-....-', 
                    '(':'-.--.', ')':'-.--.-'}
all_cap = flag.replace('{', '').upper()
morse = [MORSE_CODE_DICT[c] for c in all_cap]
print('Morse: {}'.format(' '.join(morse)))
