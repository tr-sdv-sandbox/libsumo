/**
 * @file platform_linux.c
 * @brief Linux platform implementation (for testing and development).
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sumo/policy.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Linux: persist policy to files in /tmp or a configurable directory */

/* TODO: implement file-backed storage for sumo_storage_ops_t */
