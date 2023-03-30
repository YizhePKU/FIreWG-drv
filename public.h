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

void rsInit();

bool rsIsAppTracked(
	const UINT8* appId, // UTF-16
	UINT32 appIdSize // length of appId in bytes
);

void rsRegisterConnection(
	const UINT8* appId, // UTF-16
	UINT32 appIdSize, // length of appId in bytes
	UINT8 protocol,
	UINT16 localPort
);

void rsHandleInboundPacket(void* buf, ULONG size);
void rsHandleOutboundPacket(void* buf, ULONG size);