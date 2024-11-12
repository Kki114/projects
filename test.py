length = 16
src = 'This is more than 16 characters in length.'
src_len = len(src)
print(f'Length of src is {src_len} characters, including spaces.')
#src = '0123456789ABCDEFFEDCBA9876543210'
results = list()
FILTER = ''.join(
    [(len(repr(chr(i))) == 3) and chr(i) or '.' for i in range(256)])
TEST = ''.join([(len(repr(chr(i))) > 3) and repr(chr(i)) or '.' for i in range(256)])
print(FILTER)
#print(TEST)
print(repr(chr(31)))
#print(FILTER.find(' ')); print(FILTER.rfind(' '))

#print(FILTER)
#for letter in src:
#    print(ord(letter))

for i in range(0, len(src), length):
    word = str(src[i:i+length])
    #print(word)
    printable = word.translate(FILTER)
    #print(printable)
    hexa = ' '.join([f'{ord(c):02X}' for c in word])
    print(f'\n\nhexa: {hexa}\n')
    hexwidth = length*3  # 16 * 3 = 48
    print(f'hexwidth: {hexwidth}\n')
    #print(f'{i:04x}') 
    print(f'{hexa:<{hexwidth}}, length is {len(hexa)}')
    print(f'{printable}')
    results.append(f'{i:04x} {hexa:<{hexwidth}} {printable}')
    print(results)
    #for line in results: print(f'Line {i} of results: {line}')

