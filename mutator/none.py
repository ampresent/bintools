import struct
from mutator import mutator

class none(mutator):
    def __init__(self, args):
        super(none, self).__init__(args)
        self.data_type = args['type']
        self.sizes = {
            'int': 4,
            'uint': 4,
            'str': -1
        }
        self.recipe = {
            'int': lambda x: hex(struct.unpack('<i', x)[0]),
            'uint': lambda x: hex(struct.unpack('<I', x)[0]),
            'str': lambda x: x
        }
    def get_request_len(self):
        return self.sizes[self.data_type]
    def mutate(self, raw):
        return raw
    def display(self, raw):
        return self.recipe[self.data_type](raw)
