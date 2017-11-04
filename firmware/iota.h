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

#ifndef __IOTA_H__
#define __IOTA_H__

#include <stdint.h>
#include <stdbool.h>

struct iota_data_struct {
	char seed[81];
	bool seed_ready;
};

void iota_initialize(uint32_t seed_index, bool force_index);
const char *iota_get_seed(void);
void iota_address_from_seed_with_index(uint32_t index, bool display, char public_address[]);
const char* iota_sign_transaction(const char* to_address, uint64_t amount, uint64_t balance, uint64_t timestamp, uint32_t seed_index, uint32_t remainder_index, char bundle_hash[], char first_signature[], char second_signature[]);

#endif
