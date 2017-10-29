/*
 * This file is part of the IOTA-TREZOR project.
 *
 * Copyright (C) 2017 Bart Slinger <bartslinger@gmail.com>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "iota.h"
#include "fsm.h"
#include "layout2.h"
#include "messages.h"
#include "storage.h"
#include "vendor/iota/kerl.h"
#include "vendor/iota/conversion.h"
#include "vendor/iota/addresses.h"
#include <stdio.h>

static struct iota_data_struct iota_data;

const char* iota_get_seed()
{
	if (iota_data.seed_ready) {
		// seed already generated
		return iota_data.seed;
	} else {
		// generate seed from mnemonic
		const uint8_t* trezor_seed = storage_getSeed(true);
		kerl_initialize();

		// Absorb 4 times using sliding window:
		// Divide 64 byte trezor-seed in 4 sections of 16 bytes.
		// 1: [123.] first 48 bytes
		// 2: [.123] last 48 bytes
		// 3: [3.12] last 32 bytes + first 16 bytes
		// 4: [23.1] last 16 bytes + first 32 bytes
		unsigned char bytes_in[48];

		// Step 1.
		memcpy(&bytes_in[0], trezor_seed, 48);
		kerl_absorb_bytes(bytes_in, 48);

		// Step 2.
		memcpy(&bytes_in[0], trezor_seed+16, 48);
		kerl_absorb_bytes(bytes_in, 48);

		// Step 3.
		memcpy(&bytes_in[0], trezor_seed+32, 32);
		memcpy(&bytes_in[32], trezor_seed, 16);
		kerl_absorb_bytes(bytes_in, 48);

		// Step 4.
		memcpy(&bytes_in[0], trezor_seed+48, 16);
		memcpy(&bytes_in[16], trezor_seed, 32);
		kerl_absorb_bytes(bytes_in, 48);

		// Squeeze out the seed
		trit_t seed_trits[243];
		kerl_squeeze_trits(seed_trits, 243);
		tryte_t seed_trytes[81];
		trits_to_trytes(seed_trits, seed_trytes, 243);
		trytes_to_chars(seed_trytes, iota_data.seed, 81);

		iota_data.seed_ready = true;
	}
	return iota_data.seed;
}

const char* iota_address_from_seed_with_index(uint32_t index)
{
	const char* iota_seed = iota_get_seed();

	// Seed to trits
	trit_t seed_trits[243];
	{
		tryte_t seed_trytes[81];
		chars_to_trytes(iota_seed, seed_trytes, 81);
		trytes_to_trits(seed_trytes, seed_trits, 81);
	}

	{
		tryte_t pubkey_addr[81];
		trit_t private_key_trits[243*27*2];
		generate_private_key(seed_trits, index, private_key_trits);
		trit_t public_address_trits[243];
		generate_public_address(private_key_trits, public_address_trits);

		trits_to_trytes(public_address_trits, pubkey_addr, 243);
		trytes_to_chars(pubkey_addr, iota_data.current_address, 81);
	}

	//sprintf(iota_data.current_address, "has idx in storage? %d. It is: %u.", storage.has_iota_address_index, (unsigned int)storage.iota_address_index);

	return iota_data.current_address;
}
