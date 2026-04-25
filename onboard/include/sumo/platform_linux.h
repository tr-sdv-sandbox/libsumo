/**
 * @file platform_linux.h
 * @brief File-backed Linux platform implementation of sumo_platform_ops_t
 *        and sumo_storage_ops_t — for development hosts and CI test rigs.
 *
 * All paths are rooted under a configurable directory. Storage keys map
 * to files of the same name; the kv-store writes atomically via tmp +
 * rename. The fetch callback handles `file://` URIs and bare paths.
 * Component-id-keyed writes/swaps go under a `<root>/staging/` subtree
 * with the component id hex-encoded as the filename.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SUMO_PLATFORM_LINUX_H
#define SUMO_PLATFORM_LINUX_H

#include "sumo/orchestrator.h"
#include "sumo/policy.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Allocate a `sumo_platform_ops_t` whose callbacks operate against
 * `root_dir`. The returned pointer must be freed with
 * sumo_linux_platform_ops_free().
 *
 * `root_dir` is copied; the pointer does not need to outlive the call.
 * Returns NULL on allocation failure or invalid root_dir.
 */
sumo_platform_ops_t *sumo_linux_platform_ops(const char *root_dir);

void sumo_linux_platform_ops_free(sumo_platform_ops_t *ops);

/**
 * Allocate a file-backed `sumo_storage_ops_t` rooted at `root_dir`.
 * Each key writes/reads a binary file of the same name (8 bytes
 * little-endian for u64/i64). Atomic write via tmp + rename.
 */
sumo_storage_ops_t *sumo_linux_storage_ops(const char *root_dir);

void sumo_linux_storage_ops_free(sumo_storage_ops_t *ops);

#ifdef __cplusplus
}
#endif
#endif /* SUMO_PLATFORM_LINUX_H */
