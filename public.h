#pragma once

#define NDIS60 TRUE

#include <initguid.h>
#include <ndis.h>
#include <wdf.h>
#include <ntddk.h>
#include <fwpmk.h>
#include <fwpsk.h>
#include <stdbool.h>

extern HANDLE injectionHandle;
extern HANDLE netBufferListPool;

// Call rsInit() with an expanded stack size of MAXIMUM_EXPANSION_SIZE (about 70 bytes)
EXPAND_STACK_CALLOUT ExpandedRsInit;

void rsInit();

bool rsIsAppTracked(
	const UINT8* appId, // UTF-16
	UINT32 appIdSize // length of appId in bytes
);

void rsRegisterConnection(
	const UINT8* appId, // UTF-16
	UINT32 appIdSize, // length of appId in bytes
	UINT8 protocol,
	UINT32 localAddress,
	UINT16 localPort,
	UINT32 remoteAddress,
	UINT16 remotePort
);

// Handles packet in rust.
// Returns true if the original packet should be permitted.
bool rsHandleInboundPacket(
	NET_BUFFER_LIST* packet, 
	ULONG compartmentId,
	ULONG interfaceIndex,
	ULONG subInterfaceIndex
);
bool rsHandleOutboundPacket(
	NET_BUFFER_LIST* packet, 
	ULONG compartmentId
);