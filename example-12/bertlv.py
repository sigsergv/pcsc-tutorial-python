# Copyright 2023 Sergey Stolyarov <sergei@regolit.com>
#
# Distributed under New BSD License.
# 
# https://opensource.org/license/bsd-3-clause/

from functools import reduce

class UnexpectedEndError(Exception):
    pass

class InvalidTagError(Exception):
    pass

class InvalidValueError(Exception):
    pass



class Tlv:
    """
    Class Tlv represents single TLV element
    """
    CONSTRUCTED = 'CONSTRUCTED'
    PRIMITIVE = 'PRIMITIVE'
    UNIVERSAL = 'UNIVERSAL'
    APPLICATION = 'APPLICATION'
    PRIVATE = 'PRIVATE'
    CONTEXT_SPECIFIC = 'CONTEXT_SPECIFIC'

    def __init__(self, t, value):
        # check tag
        if type(t) is int:
            self.tag = t
            self.tag_bytes = []
            b = t
            while True:
                if b == 0:
                    break
                self.tag_bytes.append(b & 0xFF)
                b >>= 8
            self.tag_bytes.reverse()
        elif type(t) is list:
            self.tag_bytes = t
            self.tag = reduce(lambda acc, x: (acc << 8) + x, self.tag_bytes, 0)
        else:
            raise InvalidTagError('Cannot construct a tag with provided tag data')

        if ((self.tag_bytes[0] >> 5) & 1) == 1:
            self.encoding = self.CONSTRUCTED
        else:
            self.encoding = self.PRIMITIVE
        tag_class = (self.tag_bytes[0] >> 6) & 3
        if tag_class == 0:
            self.tag_class = self.UNIVERSAL
        elif tag_class == 1:
            self.tag_class = self.APPLICATION
        elif tag_class == 2:
            self.tag_class = self.PRIVATE
        else:
            self.tag_class = self.CONTEXT_SPECIFIC

        # check value
        if type(value) is not list:
            raise InvalidValueError('Value must be a list')

        if all(map(lambda x: type(x) is Tlv, value)):
            value_type = 'tlv'
        elif all(map(lambda x: type(x) is int and x in range(256), value)):
            value_type = 'bytes'
        else:
            raise InvalidValueError('Not supported data in tag value argument')

        if value == []:
            self.value = value
        elif self.encoding == self.CONSTRUCTED:
            if value_type == 'tlv':
                self.value = value
            elif value_type == 'bytes':
                self.value = parse_bytes(value)
        else:
            if value_type == 'tlv':
                raise InvalidValueError('Incompatible value (Tlv) for encoding PRIMITIVE')
            else:
                self.value = value


    def __eq__(self, x):
        return x.tag == self.tag and x.value == self.value


    def __repr__(self):
        if self.encoding == self.CONSTRUCTED:
            value_items = []
            for t in self.value:
                value_items.append(repr(t))
            value = '[{}]'.format(','.join(value_items))
        else:
            value = '"{}"'.format(bytes(self.value).hex().upper())
        return 'Tlv(0x{:X}, {})'.format(self.tag, value)


class Parser:
    def __init__(self, data):
        self.data = data
        self.ind = 0

    def next(self):
        if self.ind >= len(self.data):
            # all TLV elements has been read successfully as we are at the end of list
            return None

        if self.data[self.ind] == 0x00:
            # skip zeroes before, after or between tags
            self.ind += 1
            return False

        try:
            tag_bytes = self.read_tag()
            if len(tag_bytes) > 4:
                raise InvalidTagError('Tag is too long')
            length = self.read_length()
            value = self.data[self.ind : self.ind + length]
            if len(value) != length:
                raise UnexpectedEndError()
            self.ind += length
            t = Tlv(tag_bytes, value)
        except IndexError:
            raise UnexpectedEndError()
        return t

    def read_tag(self):
        start_ind = self.ind
        b = self.data[self.ind]
        if b & 0x1F == 0x1F:
            # b = xxx1 1111, i.e. tag continues in later octets
            while True:
                self.ind += 1
                if ((self.data[self.ind] >> 7) & 1) == 0:
                    # stop if most significant bit is 0
                    break
        self.ind += 1
        return self.data[start_ind : self.ind]

    def read_length(self):
        start_ind = self.ind
        v = (self.data[self.ind] >> 7) & 1
        if v == 0:
            length = self.data[self.ind] & 0x7F
            self.ind += 1
        else:
            # length encoded in more than one octet
            length_octets_length = self.data[self.ind] & 0x7F
            if length_octets_length > 4:
                raise UnexpectedEndError('Value length value is too long ({length_octets_length})')
            length = 0
            for i in range(length_octets_length):
                x = self.data[start_ind + i + 1]
                length = (length << 8) + x
            self.ind += length_octets_length + 1
        return length


def parse_bytes(data):
    """
    Parse list of bytes into a list of Tlv class objects
    """
    parser = Parser(data)
    res = []
    while True:
        t = parser.next()
        if t is False:
            # skip zero blocks
            continue
        if t is None:
            # reached end of data
            break
        res.append(t)
    return res


def find_tag(tag, tags):
    for t in tags:
        if t.tag == tag:
            return t
    return None
