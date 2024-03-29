# Implements TLV subset defined for NFC Type 2 Tags.

from struct import unpack, pack

class TLV:
    def __init__(self, tag, value):
        self.tag = tag
        self.value = value

    def __repr__(self):
        return 'TLV({:02X}, {})'.format(self.tag, str(self.value))


def parse_bytes_list(data):
    """ Parse list of bytes and return list of parsed TLV objects.
    """
    res = []
    pos = 0

    while True:
        try:
            # expecting TLV object at position `pos`
            tag = data[pos]
            if tag == 0:
                # skip NULL TLV
                continue
            if tag == 0xFE:
                # stop when Terminator TLV is reached
                break
            pos += 1

            length = data[pos]
            pos += 1
            if length == 0xFF:
                # long length format, read next two bytes
                length = unpack('>H', bytes(data[pos:pos+2]))[0]
                pos += 2

            # read next `length` bytes
            value = data[pos:pos+length]
            res.append(TLV(tag, value))
            pos += length
        except IndexError:
            break

    return res


def pack_tlv_list(tlvs):
    """ Pack list of TLV object back to bytes list.
    """
    data = []

    for tlv in tlvs:
        data.append(tlv.tag)
        length = len(tlv.value)
        if length < 0xFE:
            data.append(length)
        else:
            data.extend(list(pack('>H', length)))
        data.extend(tlv.value)

    data.append(0xFE)  # add Terminator TLV

    return data

def parse_lock_control_bytes(data):
    # code taken from https://github.com/nfcpy/nfcpy/blob/master/src/nfc/tag/tt1.py
    page_addr = data[0] >> 4
    byte_offs = data[0] & 0x0F
    rsvd_size = ((data[1] if data[1] > 0 else 256) + 7) // 8
    page_size = 2 ** (data[2] & 0x0F)
    rsvd_from = page_addr * page_size + byte_offs
    return (rsvd_from, rsvd_from + rsvd_size)


def parse_memory_control_bytes(data):
    # code taken from https://github.com/nfcpy/nfcpy/blob/master/src/nfc/tag/tt1.py
    page_addr = data[0] >> 4
    byte_offs = data[0] & 0x0F
    rsvd_size = data[1] if data[1] > 0 else 256
    page_size = 2 ** (data[2] & 0x0F)
    rsvd_from = page_addr * page_size + byte_offs
    return (rsvd_from, rsvd_from + rsvd_size)
