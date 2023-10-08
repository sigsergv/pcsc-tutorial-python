# Copyright 2023 Sergey Stolyarov <sergei@regolit.com>
#
# Distributed under New BSD License.
# 
# https://opensource.org/license/bsd-3-clause/

from smartcard.util import toHexString, HexListToBinString


def emv_object_name(tag):
	if tag in OBJECT_TAG_MAPPINGS:
		return OBJECT_TAG_MAPPINGS[tag][0]
	else:
		return '0x{:X}'.format(tag)


def emv_object_repr(tag, value):
	if tag in OBJECT_TAG_MAPPINGS:
		d = OBJECT_TAG_MAPPINGS[tag]
		if len(d) == 1:
			# repr fun is not defined
			return bytes_to_hex(value)
		else:
			return d[1](value)
	else:
		return bytes_to_hex(value)


def bcd_byte_to_int(b):
	"""
	Convert BCD (Binary Coded Decimal) byte to Decimal
	"""
	lb = b & 0xF
	hb = (b >> 4) & 0xF
	return hb * 10 + lb


def bcd_to_int(data):
	"""
	Convert BCD encoded numeric (format "n 1", "n 6" etc) to integer.
	See section "4.3 Data Element Format Conventions" in book 4 EMV_4.3
	"""
	nibbles = []
	for b in data:
		nibbles.append((b >> 4) & 0xF)
		nibbles.append(b & 0xF)
	res = ''
	padding = True
	for n in nibbles:
		if n == 0 and padding:
			continue
		padding = False
		res += '{:01d}'.format(n)
	return '{} ({})'.format(res,  bytes_to_hex(data))


def bytes_to_string(data):
	"""
	Convert bytes list to string value coded in ISO-8859-1
	"""
	return HexListToBinString(data)


def cn_to_string(data):
	"""
	Convert Compressed numeric data (cn) to plain string representation.
	See section "4.3 Data Element Format Conventions" in book 4 EMV_4.3
	"""
	nibbles = []
	for b in data:
		nibbles.append((b >> 4) & 0xF)
		nibbles.append(b & 0xF)
	res = ''
	for n in nibbles:
		if n == 0xF:
			break
		res += '{:01X}'.format(n)
	return '{} ({})'.format(res,  bytes_to_hex(data))


def bytes_to_date(data):
	"""
	Convert YYMMDD HCD to YYYY-MM-DD
	"""
	return '{:04d}-{:02d}-{:02d}'.format(2000 + bcd_byte_to_int(data[0]), bcd_byte_to_int(data[1]), bcd_byte_to_int(data[2]))


def bytes_to_hex(data):
	return 'hex({})'.format(toHexString(data))


# each value is a tuple of 1 or 2 elements: NAME and REPR function
OBJECT_TAG_MAPPINGS = {
	0x56: ('Track 1 Data',),
	0x57: ('Track 2 Equivalent Data',),
	0x5A: ('Application Primary Account Number (PAN)', cn_to_string),
	0x5F20: ('Cardholder Name', bytes_to_string),
	0x5F24: ('Application Expiration Date', bytes_to_date),
	0x5F25: ('Application Effective Date', bytes_to_date),
	0x5F28: ('Issuer Country Code (ISO 3166)', bcd_to_int),
	0x5F30: ('Service Code',),
	0x5F34: ('Application Primary Account Number (PAN) Sequence Number', bcd_to_int),
	0x8C: ('Card Risk Management Data Object List 1 (CDOL1)',),
	0x8D: ('Card Risk Management Data Object List 2 (CDOL2)',),
	0x8E: ('Cardholder Verification Method (CVM) List',),
	0x8F: ('Certification Authority Public Key Index',),
	0x90: ('Issuer Public Key Certificate',),
	0x92: ('Issuer Public Key Remainder',),
	0x93: ('Signed Static Application Data',),
	0x9F07: ('Application Usage Control',),
	0x9F08: ('Application Version Number',),
	0x9F0D: ('Issuer Action Code - Default',),
	0x9F0E: ('Issuer Action Code - Denial',),
	0x9F0F: ('Issuer Action Code - Online',),
	0x9F1F: ('Track 1 Discretionary Data',),
	0x9F32: ('Issuer Public Key Exponent',),
	0x9F42: ('Application Currency Code (ISO 4217)', bcd_to_int),
	0x9F44: ('Application Currency Exponent',),
	0x9F46: ('ICC Public Key Certificate',),
	0x9F47: ('ICC Public Key Exponent',),
	0x9F48: ('ICC Public Key Remainder',),
	0x9F49: ('Dynamic Data Authentication Data Object List (DDOL)',),
	0x9F4A: ('Static Data Authentication Tag List',),
	0x9F62: ('PCVC3 (Track1)',),
	0x9F63: ('PUNATC (Track1)',),
	0x9F64: ('NATC (Track1)',),
	0x9F65: ('PCVC3 (Track2)',),
	0x9F66: ('Terminal Transaction Qualifiers (TTQ)',),
	0x9F67: ('NATC (Track2)',),
	0x9F68: ('Card Additional Processes',),
	0x9F6B: ('Track 2 Data/Card CVM Limit',),
	0x9F6C: ('Card Transaction Qualifiers (CTQ)',)
}


