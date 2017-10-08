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

static CONFIDENTIAL char iota_seed[81];
bool iota_seed_ready = false;

char* iota_get_seed()
{
    if (iota_seed_ready) {
        // seed already generated
        return iota_seed;
    } else {
        // generate seed from mnemonic
        const uint8_t* trezor_seed = storage_getSeed(true);
        (void) trezor_seed;
    }
    return NULL;
}
