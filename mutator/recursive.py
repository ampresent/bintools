import mutator
import itertools
import Queue

class recursive_mutator(mutator):
    def __init__(self, args):
        if type(args['length']) != 'int':
            raise
        super(mutator, self).__init__(args)
        self.ripe = None
        self.prev_collide_set = set()
    def set_context(self, dbg, handler):
        self.prev_collide_set = self.handler['collide']['collide_set']
        self.coverage_incremental_thredshold = self.handler['collide']['coverage_incremental_thredshold']
    def get_request_len(self):
        pass
    def cook(self, raw):
        return raw
    def mutate(self, ripe):
        if not self.ripe:
            self.ripe = ripe
            self.mutator = self.__iter_mutate()
        elif self.ripe != ripe:
            raise
        return self.mutator.next()
    def display(self, ripe):
        return ripe
    def __iter_mutate(self):
        indset = set(range(self.length[0]))
        q = Queue.Queue()
        q.put((set(), self.ripe))
        while q:
            (dig, s0, cs0) = q.get()
            remain = indset - dig
            for l in xrange(1, len(remain) + 1):
                for indices in itertools.permutation(remain , l):
                    for substitue in itertools.product(self.charset, repeat=l):
                        s = s0
                        for i in xrange(l):
                            s[indices[i]] = substitue[i]
                        yield s
                        if len(self.prev_collide_set - cs0) > self.coverage_incremental_thredshold:
                            q.put((dig + indices, s, self.prev_collide_set))
        print '[-] Mutator exhausted'
        raise
