#pragma once

#include "public.h"

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

// Add a callout with given GUID, callbacks, display name, and applicable layer.
// Returns the ID of the callout added, or 0 if failed to add the callout.
UINT32 addCallout(
	WDFDEVICE device,
	HANDLE filterEngine,
	GUID calloutKey,
	FWPS_CALLOUT_CLASSIFY_FN3 classifyFn,
	FWPS_CALLOUT_NOTIFY_FN3 notifyFn,
	wchar_t* displayName,
	GUID applicableLayer
);

// Allocate a NET_BUFFER_LIST from a NET_BUFFER_LIST_POOL, or NULL if failed to allocate one.
// The netBufferList is initialized with memory of `size` bytes.
NET_BUFFER_LIST* newNetBufferList(HANDLE pool, ULONG size);

// Get a pointer to the actual buffer of a NET_BUFFER_LIST (assuming it only has one NET_BUFFER).
void* getBuffer(NET_BUFFER_LIST* netBufferList);

// Get the size of the buffer of a NET_BUFFER_LIST (assuming it only has one NET_BUFFER).
ULONG getBufferSize(NET_BUFFER_LIST* netBufferList);