import itertools
import mutator

class heuristic_mutator(mutator):
    def __init__(self, args):
        super(mutator, self).__init__(args)
        self.length_now = self.length.next()
        self.mutator = itertools.product(self.charset, repeat=self.length_now)
    def get_request_len(self):
        return self.length_now
    def cook(self, raw):
        return raw
    def mutate(self, ripe):
        try:
            return self.mutator.next()
        except:
            print '[+] try next length'
        try:
            self.length_now = self.mutator.next()
            self.mutator = itertools.product(self.charset, repeat=self.length_now)
            return self.mutator.next()
        except:
            print '[-] mutator exhausted'
    def display(self, ripe):
        return ripe
