from idaapi import *
import math
import pickle

def HSL_to_RGB(h,s,l):
    ''' Converts HSL colorspace (Hue/Saturation/Value) to RGB colorspace.
        Formula from http://www.easyrgb.com/math.php?MATH=M19#text19

        Input:
            h (float) : Hue (0...1, but can be above or below
                              (This is a rotation around the chromatic circle))
            s (float) : Saturation (0...1)    (0=toward grey, 1=pure color)
            l (float) : Lightness (0...1)     (0=black 0.5=pure color 1=white)

        Ouput:
            (r,g,b) (integers 0...255) : Corresponding RGB values

        Examples:
            >>> print HSL_to_RGB(0.7,0.7,0.6)
            (110, 82, 224)
            >>> r,g,b = HSL_to_RGB(0.7,0.7,0.6)
            >>> print g
            82
    '''
    def Hue_2_RGB( v1, v2, vH ):
        while vH<0.0: vH += 1.0
        while vH>1.0: vH -= 1.0
        if 6*vH < 1.0 : return v1 + (v2-v1)*6.0*vH
        if 2*vH < 1.0 : return v2
        if 3*vH < 2.0 : return v1 + (v2-v1)*((2.0/3.0)-vH)*6.0
        return v1

    if not (0 <= s <=1): raise ValueError,"s (saturation) parameter must be between 0 and 1."
    if not (0 <= l <=1): raise ValueError,"l (lightness) parameter must be between 0 and 1."

    r,b,g = (l*255,)*3
    if s!=0.0:
       if l<0.5 : var_2 = l * ( 1.0 + s )
       else     : var_2 = ( l + s ) - ( s * l )
       var_1 = 2.0 * l - var_2
       r = 255 * Hue_2_RGB( var_1, var_2, h + ( 1.0 / 3.0 ) )
       g = 255 * Hue_2_RGB( var_1, var_2, h )
       b = 255 * Hue_2_RGB( var_1, var_2, h - ( 1.0 / 3.0 ) )

    return (int(round(r)),int(round(g)),int(round(b)))


def iter_lines(t):
    last_line = None
    for i in t:
        if last_line:
            yield(last_line, i)
        last_line = i


def entropy(prb):
    etr = dict()
    for l0, val in prb.iteritems():
        etr[l0] = 0
        for p in val.itervalues():
            etr[l0] += -1 * p * math.log(p)
    return etr

def probability(trace):
    prb = dict()
    for t in trace:
        for l0,l1 in iter_lines(t):
            if l0 not in prb:
                prb[l0] = dict()
            if l1 in prb[l0]:
                prb[l0][l1] += 1
            else:
                prb[l0][l1] = 1
    for l0, val in prb.items():
        s = sum(prb[l0].values())
        for l1 in val.iterkeys():
            prb[l0][l1] /= float(s)
    return prb


trace = []
for parent, dirnames, filenames in os.walk('c:\\trace'):
    for fname in filenames:
        with open(os.path.join(parent, fname)) as f:
            trace.append(pickle.load(f))

prb = probability(trace)
etr = entropy(prb)

for ip, e in etr.iteritems():
	# 0xBGR
	# blue -> cyan -> green -> yellow -> red
	depth = (1-e)*2.0/3.0
	r,g,b = HSL_to_RGB(depth, 1, 0.5)
	color = (r | (g<<8) | (b<<16))
	SetColor(ip, CIC_ITEM, color)
