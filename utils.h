#pragma once

#define NDIS60 TRUE

#include <initguid.h>
#include <ndis.h>
#include <wdf.h>
#include <ntddk.h>
#include <fwpmk.h>
#include <fwpsk.h>

// Create a WDFDRIVER with an unload function.
// Returns NULL if failed to create the driver.
WDFDRIVER createDriver(
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath,
	PFN_WDF_DRIVER_UNLOAD DriverUnload
);

// Create a control device with given name.
// Returns NULL if failed to create the device.
WDFDEVICE createDevice(WDFDRIVER driver, UNICODE_STRING deviceName);

// Create an injection handle.
// Returns NULL if failed to create the injection handle.
HANDLE createInjectionHandle();

// Creates a handle to the filter engine.
// Returns NULL if failed to open the filter engine.
HANDLE openFilterEngine();

// Allocate a NET_BUFFER_LIST_POOL, or NULL if failed to allocate one.
HANDLE newNetBufferListPool();

// Allocate a NET_BUFFER_LIST from a NET_BUFFER_LIST_POOL, or NULL if failed to allocate one.
// The netBufferList is initialized with memory of `size` bytes.
NET_BUFFER_LIST* newNetBufferList(HANDLE pool, ULONG size);

// Get a pointer to the actual buffer of a NET_BUFFER_LIST (assuming it only has one NET_BUFFER).
void* getBuffer(NET_BUFFER_LIST* netBufferList);