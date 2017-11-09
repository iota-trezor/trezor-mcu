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
#include "gettext.h"
#include "layout2.h"
#include "messages.h"
#include "storage.h"
#include "vendor/iota/kerl.h"
#include "vendor/iota/conversion.h"
#include "vendor/iota/addresses.h"
#include "vendor/iota/transaction.h"
#include <stdio.h>

static struct iota_data_struct iota_data;

void iota_address_generation_progress_callback(uint32_t progress)
{
	layoutProgress(_("Generating address."), progress);
}

void iota_initialize(uint32_t seed_index, bool force_index)
{
	// Has to be called before calling any of the other functions in this file.
	// It does the following steps:
	// 1. Get seed from mnemonic
	// 2. Check if there is a first address, generate if not
	// 3. Check if there is a next address, generate if not

	// We will always need the seed, doesn't take much time.
	iota_get_seed();

	// Are we forcing the seed index to some value?
	if (force_index) {
		storage_setIotaAddressesInvalid();
		storage_setIotaAddressIndex(seed_index);

	} else if (storage.has_iota_address_index) {
		seed_index = storage.iota_address_index;

	} else {
		// No index in storage, start at zero
		storage_setIotaAddressesInvalid();
		storage_setIotaAddressIndex(0);
		seed_index = 0;
	}

	// Now we have the seed index. Check if we have the addresses. If not, generate
	if (!storage.has_iota_address || !storage.has_iota_next_address) {
		iota_address_from_seed_with_index(seed_index, false, storage.iota_address);
		iota_address_from_seed_with_index(seed_index+1, false, storage.iota_next_address);
		storage.has_iota_address = true;
		storage.has_iota_next_address = true;
		storage_commit();
	}
}

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

void iota_address_from_seed_with_index(uint32_t index, bool display, char public_address[])
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
		generate_public_address(private_key_trits, public_address_trits, iota_address_generation_progress_callback);

		trits_to_trytes(public_address_trits, pubkey_addr, 243);
		trytes_to_chars(pubkey_addr, public_address, 81);
	}

	if(display) {
		layoutIotaAddress(public_address, "IOTA  receive address:");
	}
}

// Returns the bundle hash
const char* iota_sign_transaction(const char* to_address, uint64_t amount, uint64_t balance, uint64_t timestamp, uint32_t seed_index, uint32_t remainder_index, char bundle_hash[], char first_signature[], char second_signature[])
{
	(void) seed_index;
	(void) remainder_index;
	(void) first_signature;
	(void) second_signature;
	const char tag[] = "TREZOR999999999999999999999";
	// Step one is to find out the current address and the next address.

	//char remainder_address[81];
	//iota_address_from_seed_with_index(remainder_index, false, remainder_address);

	//char from_address[81];
	//iota_address_from_seed_with_index(seed_index, false, from_address);

	tryte_t normalized_bundle_hash[81];
	{
		tryte_t bundle_hash_trytes[81];
		calculate_standard_bundle_hash(storage.iota_address, to_address, storage.iota_next_address, balance, amount, tag, timestamp, bundle_hash_trytes);
		trytes_to_chars(bundle_hash_trytes, bundle_hash, 81);
		normalize_hash(bundle_hash_trytes, normalized_bundle_hash);
	}

	// We will also need the private key of the first address
	// Seed to trits
	trit_t seed_trits[243];
	{
		tryte_t seed_trytes[81];
		chars_to_trytes(iota_data.seed, seed_trytes, 81);
		trytes_to_trits(seed_trytes, seed_trits, 81);
	}

	trit_t private_key_trits[243*27*2];
	generate_private_key(seed_trits, storage.iota_address_index, private_key_trits);

	// Sign inputs
	if(1){
		trit_t first_signature_trits[3*27*81];
		tryte_t first_signature_trytes[27*81];
		generate_signature_fragment(&normalized_bundle_hash[0], &private_key_trits[0], first_signature_trits);
		trits_to_trytes(first_signature_trits, first_signature_trytes, 3*27*81);
		trytes_to_chars(first_signature_trytes, first_signature, 27*81);
	}

	if(1){
		trit_t second_signature_trits[3*27*81];
		tryte_t second_signature_trytes[27*81];
		generate_signature_fragment(&normalized_bundle_hash[27], &private_key_trits[6561], second_signature_trits);
		trits_to_trytes(second_signature_trits, second_signature_trytes, 3*27*81);
		trytes_to_chars(second_signature_trytes, second_signature, 27*81);
	}

	return NULL;
}
