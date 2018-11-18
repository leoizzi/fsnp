/*
 *   SHA-256 implementation, Mark 2
 *
 *   Copyright (c) 2010,2014 Ilya O. Levin, http://www.literatecode.com
 *
 *   Permission to use, copy, modify, and distribute this software for any
 *   purpose with or without fee is hereby granted, provided that the above
 *   copyright notice and this permission notice appear in all copies.
 *
 *   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifndef SHA256_H_
#define SHA256_H_

#include <stddef.h>
#include <stdint.h>

#include "compiler.h"

#define SHA256_BYTES 32
typedef uint8_t sha256_t[SHA256_BYTES];

FSNP_BEGIN_DECL

EXPORT void sha256(const void *data, size_t len, sha256_t hash);

#define STRINGIFY_HASH(key_str, key, i) \
	for (i = 0; i < SHA256_BYTES; i++) { \
		snprintf(&key_str[i], sizeof(uint8_t) + 1, "%hhx", key[i]); \
	}

FSNP_END_DECL

#endif //SHA256_H_
