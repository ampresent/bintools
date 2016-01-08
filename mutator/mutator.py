import itertools
class mutator(object):
    def __init__(self, args):
        # args support: length, charset, badchar
        self.length = None
        self.charset = set()
        if 'length' in args:
            if isinstance(args['length'], int):
                self.length = itertools.repeat(args['length'])
            elif isinstance(args['length'], (str,unicode)):
                s = args['length'].strip()
                if s.startswith('>='):
                    s = s[2:].strip()
                    if s.isdigit():
                        self.length = itertools.count(int(s), 1)
                elif s.startswith('<='):
                    s = s[2:].strip()
                    if s.isdigit():
                        self.length = itertools.count(int(s), -1)
                elif s.startswith('<'):
                    s = s[1:].strip()
                    if s.isdigit():
                        self.length = itertools.count(int(s)-1, -1)
                elif s.startswith('>'):
                    s = s[1:].strip()
                    if s.isdigit():
                        self.length = itertools.count(int(s)+1, 1)
                elif s.startswith('between(') and s.endswith(')'):
                    s = s[8:-1]
                    i = s.find(',')
                    a = s[0:i].strip()
                    b = s[i+1:].strip()
                    if i > 0 and a.isdigit() and b.isdigit():
                        self.length = iter(xrange(int(a), int(b)+1))
            elif isinstance(args['length'], (list, set, tuple)):
                self.length = iter(args['length'])
        if 'charset' in args:
            if isinstance(args['charset'], (str,unicode)):
                self.charset = set(args['charset'])
            if isinstance(args['charset'], (list, set, tuple)):
                if 'alpha' in args['charset']:
                    self.charset.update('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
                if 'upper' in args['charset']:
                    self.charset.update('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
                if 'lower' in args['charset']:
                    self.charset.update('abcdefghijklmnopqrstuvwxyz')
                if 'num' in args['charset']:
                    self.charset.update('0123456789')
                if 'dir' in args['charset']:
                    self.charset.update('./')
        else:
            self.charset = set(map(chr, range(1, 256)))
        if 'badchar' in args:
            if isinstance(args['badchar'], (str, list, tuple, set, unicode)):
                self.charset -= set(args['badchar'])
    def set_context(self, sandbox, dbg, handler):
        self.sandbox = sandbox
        self.dbg = dbg
        self.handler = handler
    # Return -1 if it's undetermined
    def get_request_len(self):
        pass
    def mutate(self, raw):
        pass
    def display(self, raw):
        pass
