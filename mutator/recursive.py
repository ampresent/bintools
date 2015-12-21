from mutator import mutator
import itertools
import Queue

class recursive(mutator):
    def __init__(self, args):
        super(recursive, self).__init__(args)
        self.ripe = None
        self.prev_collide_set = set()
        if 'trace_bp' not in args:
            print '[-] No adaptive trace handler specified.'
            raise
        self.trace_bp = args['trace_bp']
    def set_context(self, sandbox, dbg, handler):
        trace_handler = filter(lambda x:'collide' in x, sandbox.handlers[self.trace_bp])
        if not trace_handler:
            print '[-] No adaptive trace handler found.'
            raise
        if len(trace_handler) > 1:
            print '[-] More than one adaptive trace handler found.'
            raise
        trace_handler = trace_handler[0]
        self.prev_collide_set = trace_handler['collide']['collide_set']
        self.coverage_incremental_thredshold = trace_handler['collide']['coverage_incremental_thredshold']
    def get_request_len(self):
        return -1
    def cook(self, raw):
        return raw
    def mutate(self, ripe):
        if not self.ripe:
            self.ripe = ripe
            self.mutator = self.__iter_mutate()
        return self.mutator.next()
    def display(self, ripe):
        return ripe
    def __iter_mutate(self):
        yield ''
        indset = set(range(len(self.ripe)))
        q = Queue.Queue()
        q.put((set(), self.ripe, self.prev_collide_set))
        while q:
            (dig, s0, cs0) = q.get()
            remain = indset - dig
            for l in xrange(1, len(remain) + 1):
                for indices in itertools.permutations(remain , l):
                    for substitue in itertools.product(self.charset, repeat=l):
                        s = list(s0)
                        for i in xrange(l):
                            s[indices[i]] = substitue[i]
                        s = ''.join(s)
                        yield s
                        if len(self.prev_collide_set - cs0) > self.coverage_incremental_thredshold:
                            q.put((dig + indices, s, self.prev_collide_set))
        print '[-] Mutator exhausted'
        raise
