import argparse
import struct
import sys

avai_f = ['b', 'h', 'w', 'g']
avai_u = ['x', 'd', 'u', 'o', 't', 'i', 'c', 'f']
avai = avai_u + avai_f

def parse():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-a', '--add', action='store_const', const='add', dest='utility')
    group.add_argument('-r', '--remove', action='store_const', const='remove', dest='utility')
    group.add_argument('-m', '--modify', action='store_const', const='modify', dest='utility')
    # SHOULD SUPPORT 16bit
    parser.add_argument('-s', '--start', type=int, default=0, action='store', dest='start')
    parser.add_argument('-l', '--length', type=int, action='store', default=-1, dest='length')
    parser.add_argument('-t', '--type', choices=avai, action='store', dest='type', nargs=2, default='wx')
    parser.add_argument('-i', '--input', type=argparse.FileType('r'), default=open('/dev/null'), action='store', dest='input')

    parser.add_argument('-o', '--output', type=argparse.FileType('w'), action='store', default=sys.stdout, dest='output')
    option = parser.parse_args()

    option.raw = option.input.read().strip().split()
    option.input.close()

    a = 'f' if option.type[0] in avai_f else 'u'
    b = 'f' if option.type[1] in avai_f else 'u'

    if option.utility == 'remove' and option.length<0:
        raise
    if a == b:
        parser.print_usage()
        return None
    if a == 'u':
        option.u = option.type[0]
        option.f = option.type[1]
    else:
        option.u = option.type[1]
        option.f = option.type[0]

    return option

def reformat(u, f, raw):
    if u == 'c':
        ripe = raw
    elif u == 'f':
        if f == 'w':
            pack_format = 'f'
        elif f == 'g':
            pack_format = 'd'
        ripe = ''.join(map(lambda x:struct.pack("<"+pack_format,float(x)), raw))
    else:
        pack_format = {'b':'B', 'h':'H', 'w':'I', 'g':'Q'}[f]
        if u == 'd':
            f = f.lower()
        base = {'x':16,'d':1,'u':1,'o':8,'t':2}
        ripe = ''.join(map(lambda x:struct.pack("<"+pack_format,int(x, base[u])), raw))
    return ripe

def modify(binary, ripes):
    sorted_ripes = ripes[::-1]
    output = []
    for i, c in enumerate(binary):
        ok = False
        for o in sorted_ripes:
            if o.utility == 'add':
                if o.start == i:
                    output.append(o)
                    output.append(c)
                    ok = True
                    break
            elif o.utility == 'remove':
                if o.start<=i<o.start+o.length:
                    ok = True
                    break
            elif o.utility == 'modify':
                if o.start<=i<o.start+len(o):
                    output.append(o[i-o.start])
                    ok = True
                    break
        if not ok:
            output.append(c)
    return ''.join(output)

if __name__ == '__main__':
    option = parse()
    reformat(option.u, option.f, option.raw)
    options = [option]
    binary = raw_input()
    res = modify(binary, options)
    print res
    option.output.close()
    option.input.close()
