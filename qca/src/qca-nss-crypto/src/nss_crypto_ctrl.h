/* Copyright (c) 2013, The Linux Foundation. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 *
 *
 */
#ifndef __NSS_CRYPTO_CTRL_H
#define __NSS_CRYPTO_CTRL_H

#define NSS_CRYPTO_IDX_BITS	~(0x1 << NSS_CRYPTO_MAX_IDXS)


/**
 * @brief max key lengths supported for various algorithms
 */
enum nss_crypto_keylen_supp {
	NSS_CRYPTO_KEYLEN_AES128 = 16,		/**< AES-128 bit */
	NSS_CRYPTO_KEYLEN_AES256 = 32,		/**< AES-256 bit */
	NSS_CRYPTO_KEYLEN_SHA1HMAC = 20,	/**< SHA1-HMAC */
	NSS_CRYPTO_KEYLEN_SHA256HMAC = 32,	/**< SHA256-HMAC */
	NSS_CRYPTO_KEYLEN_DES = 8,		/**< DES-64 bit */
	NSS_CRYPTO_KEYLEN_3DES = 24,		/**< 3DES-192 bit */
};

/**
 * @brief session states
 */
enum nss_crypto_session_state {
	NSS_CRYPTO_SESSION_STATE_NONE = 0,	/**< session state none */
	NSS_CRYPTO_SESSION_STATE_ALLOC = 1,	/**< session state is alloc */
	NSS_CRYPTO_SESSION_STATE_FREE = 2	/**< session state is free */
};

struct nss_crypto_encr_cfg {
	uint32_t cfg;
	uint8_t key[NSS_CRYPTO_CKEY_SZ];
};

struct nss_crypto_auth_cfg {
	uint32_t cfg;
	uint32_t *iv;
	uint8_t key[NSS_CRYPTO_AKEY_SZ];
};

struct nss_crypto_ctrl_idx {
	struct nss_crypto_idx idx;
	struct nss_crypto_cmd_block *cblk;
};

/**
 * @brief Crypto control specific structure that describes an Engine
 */
struct nss_crypto_ctrl_eng {
	uint32_t cmd_base;	/**< base address for command descriptors (BAM prespective) */
	uint8_t *crypto_base;	/**< base address for crypto register writes */
	uint32_t bam_pbase;	/**< physical base address for BAM register writes */
	uint8_t *bam_base;	/**< base address for BAM regsiter writes */
	uint32_t bam_ee;	/**< BAM execution enivironment for the crypto engine */
	struct device *dev;	/**< HLOS device type for the crypto engine */

	struct nss_crypto_desc *hw_desc[NSS_CRYPTO_BAM_PP]; 		/**< H/W descriptors BAM rings, command descriptors */
	struct nss_crypto_ctrl_idx idx_tbl[NSS_CRYPTO_MAX_IDXS];	/**< index table */
};

/**
 * @brief Main Crypto Control structure, holds information about number of session indexes
 * number of engines etc.,
 *
 * @note currently we support 4 indexes, in future it will allocate more
 */
struct nss_crypto_ctrl {
	uint32_t idx_bitmap;		/**< session allocation bitmap, upto NSS_CRYPTO_MAX_IDXS can be used */
	uint32_t idx_state_bitmap;	/**< session state bitmap, upto NSS_CRYPTO_MAX_IDXS can be used */

	uint32_t num_idxs;	/**< number of allocated indexes */
	uint32_t num_eng;	/**< number of available engines */
	spinlock_t lock;	/**< lock */

	struct nss_crypto_ctrl_eng eng[NSS_CRYPTO_ENGINES];		/**< per engine information */
};

static inline bool nss_crypto_check_idx_state(uint32_t map, uint32_t idx)
{
	return !!(map & (0x1 << idx));
}

static inline void nss_crypto_set_idx_state(uint32_t *map, uint32_t idx)
{
	*map |= (0x1 << idx);
}

static inline void nss_crypto_clear_idx_state(uint32_t *map, uint32_t idx)
{
	*map &= ~(0x1 << idx);
}

/**
 * @brief Initialize and allocate descriptor memory for a given pipe
 *
 * @param eng[IN] Engine context for control operation
 * @param idx[IN] Pipe pair index number
 * @param desc_paddr[IN] physical address of H/W descriptor
 * @param desc_vaddr[IN] virtual address of H/W descriptor
 *
 */
void nss_crypto_pipe_init(struct nss_crypto_ctrl_eng *eng, uint32_t idx, uint32_t *desc_paddr, struct nss_crypto_desc **desc_vaddr);

/**
 * @brief initiallize the index table per engine
 *
 * @param eng[IN] per engine state
 * @param msg[OUT] message to NSS for each allocated index
 *
 * @return status of the call
 */
nss_crypto_status_t nss_crypto_idx_init(struct nss_crypto_ctrl_eng *eng, struct nss_crypto_idx *msg);

/**
 * @brief Initiallize the generic control entities in nss_crypto_ctrl
 */
void nss_crypto_ctrl_init(void);

/**
 * @brief Reset session specific parameteres.
 *
 * @param session_idx[IN] session index
 * @param state[IN] session stats (ALLOC/FREE)
 */
void nss_crypto_reset_session(uint32_t session_idx, enum nss_crypto_session_state state);

#endif /* __NSS_CRYPTO_CTRL_H*/
