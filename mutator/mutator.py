class mutator():
    def __init__(self, args):
        # args support: length, charset, badchar
        self.length = None
        self.charset = set()
        if 'length' in args:
            if type(args['length'] == 'int'):
                self.length = itertools.repeat(args['length'])
            elif type(args['length'] == 'str'):
                s = args['length'].strip()
                if s.startswith('<'):
                    s = s[1:].strip()
                    if s.isdigit():
                        self.length = itertools.count(int(s)-1, -1)
                if s.startswith('>'):
                    s = s[1:].strip()
                    if s.isdigit():
                        self.length = itertools.count(int(s)+1, 1)
                if s.startswith('>='):
                    s = s[2:].strip()
                    if s.isdigit():
                        self.length = itertools.count(int(s), 1)
                if s.startswith('<='):
                    s = s[2:].strip()
                    if s.isdigit():
                        self.length = itertools.count(int(s), -1)
                if s.startswith('between(') and s.endswith(')'):
                    s = s[8:-1]
                    i = s.find(',')
                    a = s[0:i].strip()
                    b = s[i+1:].strip()
                    if i > 0 and a.isdigit() and b.isdigit():
                        self.length = iter(xrange(int(a), int(b)+1))
            elif type(args['length']) in ['list', 'set', 'tuple']:
                self.length = args['length']
        if 'charset' in args:
            if type(args['charset']) == 'str':
                self.charset = set(args['charset'])
            if type(args['charset']) in ['list', 'set', 'tuple']:
                if 'alpha' in args['charset']:
                    self.charset.union('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
                if 'upper' in args['charset']:
                    self.charset.union('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
                if 'lower' in args['charset']:
                    self.charset.union('abcdefghijklmnopqrstuvwxyz')
                if 'numchar' in args['charset']:
                    self.charset.union('0123456789')
                if 'purenum' in args['charset']:
                    self.charset.union(set([0,1,2,3,4,5,6,7,8,9]))
                if 'dir' in args['charset']:
                    self.charset.union('./')
        else:
            self.charset = set(range(255))
        if 'badchar' in args:
            if type(args) in ['str', 'list', 'tuple', 'set']:
                self.charset -= set(args)
    def set_context(self, dbg, handler):
        self.dbg = dbg
        self.handler = handler
    def get_request_len(self):
        pass
    def cook(self, raw):
        pass
    def mutate(self, ripe):
        pass
    def display(self, ripe):
        pass
