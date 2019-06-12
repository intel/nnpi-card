/*
 * NNP-I Linux Driver
 * Copyright (c) 2019, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */

#include "icedrv_sw_trace_stub.h"
void icedrv_sw_trace_init(void)
{
}

void trace_icedrvCreateContext(uint8_t state, uint64_t ctxID,
				 uint8_t status, int reason){
}

void trace_icedrvCreateNetwork(uint8_t state, uint64_t ctxID,
	uint64_t netID, uint32_t *resource, uint8_t status, int reason){
}

void trace_icedrvExecuteNetwork(uint8_t state, uint64_t ctxID,
	uint64_t netID, uint64_t inferID, uint8_t status, int reason){
}

void trace_trace_icedrvNetworkResource(uint64_t ctxID, uint64_t netID,
	uint64_t icesReserved, uint64_t countersReserved, uint64_t llcReserved){
}

void trace_icedrvDestroyNetwork(uint8_t state, uint64_t ctxID,
			uint64_t netID, uint8_t status, int reason){
}

void trace_icedrvDestroyContext(uint8_t state, uint64_t ctxID,
				uint8_t status, int reason){
}
