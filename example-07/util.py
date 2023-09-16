def unpack_access_conditions_bits(ac_bytes):
	bit = lambda pos, b: ((b >> pos) & 1)
	#ac0 = ac_bytes[0]  # we don't need that byte
	ac1 = ac_bytes[1]
	ac2 = ac_bytes[2]
	return [
		[bit(4, ac1), bit(0, ac2), bit(4, ac2)],
		[bit(5, ac1), bit(1, ac2), bit(5, ac2)],
		[bit(6, ac1), bit(2, ac2), bit(6, ac2)],
		[bit(7, ac1), bit(3, ac2), bit(7, ac2)]
	]


def pack_access_conditions_bits(ac_bits):
	mkbit = lambda block, pos: 0 if ac_bits[block][pos]==0 else 1
	mkbit_inv = lambda block, pos: 1 if ac_bits[block][pos]==0 else 0

	b6 = 0
	b6 |= mkbit_inv(3, 1)
	b6 <<= 1
	b6 |= mkbit_inv(2, 1)
	b6 <<= 1
	b6 |= mkbit_inv(1, 1)
	b6 <<= 1
	b6 |= mkbit_inv(0, 1)
	b6 <<= 1
	b6 |= mkbit_inv(3, 0)
	b6 <<= 1
	b6 |= mkbit_inv(2, 0)
	b6 <<= 1
	b6 |= mkbit_inv(1, 0)
	b6 <<= 1
	b6 |= mkbit_inv(0, 0)

	b7 = 0
	b7 |= mkbit(3, 0)
	b7 <<= 1
	b7 |= mkbit(2, 0)
	b7 <<= 1
	b7 |= mkbit(1, 0)
	b7 <<= 1
	b7 |= mkbit(0, 0)
	b7 <<= 1
	b7 |= mkbit_inv(3, 2)
	b7 <<= 1
	b7 |= mkbit_inv(2, 2)
	b7 <<= 1
	b7 |= mkbit_inv(1, 2)
	b7 <<= 1
	b7 |= mkbit_inv(0, 2)

	b8 = 0
	b8 |= mkbit(3, 2)
	b8 <<= 1
	b8 |= mkbit(2, 2)
	b8 <<= 1
	b8 |= mkbit(1, 2)
	b8 <<= 1
	b8 |= mkbit(0, 2)
	b8 <<= 1
	b8 |= mkbit(3, 1)
	b8 <<= 1
	b8 |= mkbit(2, 1)
	b8 <<= 1
	b8 |= mkbit(1, 1)
	b8 <<= 1
	b8 |= mkbit(0, 1)

	return [b6, b7, b8]

