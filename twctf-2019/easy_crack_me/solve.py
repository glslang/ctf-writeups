from sys import argv

from pwn import *
from pwnlib.util import packing
from z3 import *


def read_from_address(p, address, size):
    return list(packing.unpack_many(p.read(address, size), 32, endian='little', sign=False))


def get_conn():
    assert len(argv) > 1
    return ELF(argv[1])


def main():
    s = get_conn()

    print('[+] Reading data from addresses')
    DAT_400f40 = read_from_address(s, 0x400f40, 0x20)
    DAT_400f60 = read_from_address(s, 0x400f60, 0x20)
    DAT_400fa0 = read_from_address(s, 0x400fa0, 0x20)
    DAT_400f80 = read_from_address(s, 0x400f80, 0x20)
    DAT_400fc0 = read_from_address(s, 0x400fc0, 0x80)

    print('[+] Creating Z3 model')

    flag = [BitVec(f'{i:2}', 32) for i in range(39)]
    s = Solver()
  
    for i, c in enumerate('TWCTF{'):
        s.add(flag[i] == ord(c))
    s.add(flag[-1] == ord('}'))


    for j in range(8):
        v = BitVecVal(0, 32)
        u = BitVecVal(0, 32)
        r = BitVecVal(0, 32)
        w = BitVecVal(0, 32)
        for i in range(4):
            u += flag[(j<<2)+i+6]
            r ^= flag[(j<<2)+i+6]
            v += flag[(i<<3)+j+6]
            w ^= flag[(i<<3)+j+6]
        s.add(u == DAT_400f40[j])
        s.add(r == DAT_400f60[j])
        s.add(v == DAT_400fa0[j])
        s.add(w == DAT_400f80[j])

    for j in range(0x20):
        if DAT_400fc0[j] == 0x80:
            s.add(flag[j+6] >= ord('a'), flag[j+6] <= ord('f'))
        else:
            s.add(flag[j+6] >= ord('0'), flag[j+6] <= ord('9'))

    total = BitVecVal(0, 32)
    for i in range(0x10):
        total += flag[(i+3)*2]
    s.add(total == 0x488)

    s.add(flag[0x25] == ord('5'))
    s.add(flag[7] == ord('f'))
    s.add(flag[0xb] == ord('8'))
    s.add(flag[0xc] == ord('7'))
    s.add(flag[0x17] == ord('2'))
    s.add(flag[0x1f] == ord('4'))

    print('[+] Verifying model satisfiability')
    assert s.check() == sat

    print('[*] Running model')

    while s.check() == sat:
        m = s.model()

        model = sorted([(d, m[d]) for d in m], key = lambda x: str(x[0]))
        candidate = ''.join([chr(m[1].as_long()) for m in model])
 
        with process([argv[1], candidate]) as p:
            result = p.readline()
            if b'Correct' in result:
                print(f'[+] Found flag: \033[92m{candidate}')
                return

        s.add(Or([f != s.model()[f] for i, f in enumerate(flag)]))

if __name__ == '__main__':
    main()
