#!/usr/bin/env python3

import unittest
import binascii

from bertlv import parse_bytes, Tlv, UnexpectedEndError, InvalidTagError, InvalidValueError

class TestTlv(unittest.TestCase):
    def test_object(self):
        # create Tlv object with tag and bytes
        t = Tlv(0x10, [0x31, 0x32])

        # create constructed tag with tag and other tags list as value
        t1 = Tlv(0x10, [0x31])
        t2 = Tlv(0x11, [0x32])
        t3 = Tlv(0x12, [0x32, 0x34, 0x35])

        # create without exception
        t = Tlv(0x35, [t1, t2, t3])

        # expecting exception
        with self.assertRaises(InvalidValueError) as cm:
            t = Tlv(0x54, [t1, t2, t3])
        assert(cm.exception.args == ('Incompatible value (Tlv) for encoding PRIMITIVE',))

    def test_parse(self):

        with self.assertRaises(UnexpectedEndError):
            parse_bytes(toBytes("01"))

        data = parse_bytes([])
        assert(data == [])

        # 1-byte tag
        data = parse_bytes(toBytes("100122"))
        assert(data == [Tlv(0x10, [0x22])])

        # 2-byte tag
        data = parse_bytes(toBytes("9F0106123456789abc"))
        assert(data == [Tlv(0x9F01, [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC])])

        # 3-byte tag
        data = parse_bytes(toBytes("DF8119021234"))
        assert(data == [Tlv(0xDF8119, [0x12, 0x34])])

        # 4-byte tag
        data = parse_bytes(toBytes("5FCEDF20021234"))
        assert(data == [Tlv(0x5FCEDF20, [0x12, 0x34])])

        # >4 bytes length tags are not valid
        with self.assertRaises(InvalidTagError):
            parse_bytes(toBytes("5FCEDFA010021234"))

        # no data
        data = parse_bytes(toBytes("1000"))
        assert(data == [Tlv(0x10, [])])

        # 2-byte length
        data = parse_bytes(toBytes("12820101"+"00"*257))
        t = data[0]
        assert(t.tag == 0x12)
        assert(len(t.value) == 257)
        assert(t.value == toBytes("00"*257))

        # incorrectly encoded value length 85 = 0b10000101
        with self.assertRaises(UnexpectedEndError):
            parse_bytes(toBytes("1285"))

        # incomplete value bytes
        with self.assertRaises(UnexpectedEndError):
            data = parse_bytes(toBytes("9F010212"))

        # multiple tags
        data = parse_bytes(toBytes("9F1001318A03414243"))
        assert(data == [Tlv(0x9F10, [0x31]), Tlv(0x8A, [0x41, 0x42, 0x43])])

        # constructed tags
        data = parse_bytes(toBytes("3F10088A03414243100100"))
        assert(data == [Tlv(0x3F10, [Tlv(0x8A, [0x41,0x42,0x43]), Tlv(0x10, [0x00])])])

        # leading zeroes
        data = parse_bytes(toBytes("00009F1001318A03414243"))
        assert(data == [Tlv(0x9F10, [0x31]),Tlv(0x8A, [0x41, 0x42, 0x43])])

        # between element padding
        data = parse_bytes(toBytes("9F10013100008A03414243"))
        assert(data == [Tlv(0x9F10, [0x31]), Tlv(0x8A, [0x41, 0x42, 0x43])])

        # trailing zeroes
        data = parse_bytes(toBytes("9F1001318A034142430000"))
        assert(data == [Tlv(0x9F10, [0x31]), Tlv(0x8A, [0x41, 0x42, 0x43])])

        # constructed tag with padding
        data = parse_bytes(toBytes("00BF100B008A034142430010010000"))
        assert(data == [Tlv(0xBF10,[Tlv(0x8A, [0x41, 0x42, 0x43]), Tlv(0x10, [0x00])])])

def toBytes(s):
    return list(binascii.unhexlify(s))


if __name__ == '__main__':
    unittest.main()