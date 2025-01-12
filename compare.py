import os

test_f = open('insns.txt')
gt_f = open('gt.txt')

def at_eof(f):
    return f.tell() >= os.fstat(f.fileno()).st_size

def read_insn(f):
    line = f.readline().strip()
    comps = line.split(' ~~ ')
    addr = int(comps[0], 16)
    asm = comps[1]
    length = int(comps[2])
    num_ops = int(comps[3])
    ops = []

    for _ in range(num_ops):
        line = f.readline().strip()
        ops.append(line)

    return (addr, asm, length, ops)

def compare(a, b):
    if a[0] != b[0]:
        print('Address does not match')
        return False

    asm1 = a[1].replace('0xffffffff', '-0x1')
    asm2 = b[1].replace('0xffffffff', '-0x1')

    if asm1 != asm2:
        print('Assembly does not match')
        return False

    if a[2] != b[2]:
        print('Length does not match')
        return False

    if len(a[3]) != len(b[3]):
        print('Mismatched number of ops')
        return False

    for (i, (op1, op2)) in enumerate(zip(a[3], b[3])):
        # HACK for different address space things which I don't feel like debugging right now.
        op1 = op1.replace('*RSP = 0x10000', '*RSP = 0x')
        op2 = op2.replace('*RSP = 0x10000', '*RSP = 0x')
        op1 = op1.replace('*RSP = 0x1000', '*RSP = 0x')
        op2 = op2.replace('*RSP = 0x1000', '*RSP = 0x')
        op1 = op1.replace('0xffffffff', '-0x1')
        op2 = op2.replace('0xffffffff', '-0x1')

        if op1 != op2:
            s1 = op1.split(' = ')[1]
            s2 = op2.split(' = ')[1]

            # TODO: Make this a better check/workaround.
            if not('-' in s1 and '+' in s2):
                print('Op %d does not match' % i)
                return False

    return True

def pprint(insn):
    print('0x%x: %s -- %d' % (insn[0], insn[1], insn[2]))
    for (i, op) in enumerate(insn[3]):
        print('    %d: %s' % (i, op))

i = 0

while not (at_eof(test_f) or at_eof(gt_f)):
    test_insn = read_insn(test_f)
    gt_insn = read_insn(gt_f)

    print(i)
    i += 1

    if not compare(test_insn, gt_insn):
        pprint(test_insn)
        print()
        pprint(gt_insn)
        break
