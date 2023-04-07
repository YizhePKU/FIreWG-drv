#include "utils.h"

WDFDRIVER createDriver(
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath,
	PFN_WDF_DRIVER_UNLOAD DriverUnload
) {
	WDF_DRIVER_CONFIG config;
	WDF_DRIVER_CONFIG_INIT(&config, NULL);
	config.DriverInitFlags = WdfDriverInitNonPnpDriver;
	config.EvtDriverUnload = DriverUnload;
	WDFDRIVER driver;
	NTSTATUS status = WdfDriverCreate(
		DriverObject,
		RegistryPath,
		WDF_NO_OBJECT_ATTRIBUTES,
		&config,
		&driver
	);
	if (!NT_SUCCESS(status)) {
		DbgPrint("WdfDriverCreate failed with status %d\n", status);
		return NULL;
	}
	return driver;
}

WDFDEVICE createDevice(WDFDRIVER driver, UNICODE_STRING deviceName) {
	PWDFDEVICE_INIT deviceInit = WdfControlDeviceInitAllocate(
		driver,
		&SDDL_DEVOBJ_KERNEL_ONLY
	);
	WdfDeviceInitSetCharacteristics(
		deviceInit,
		FILE_DEVICE_SECURE_OPEN,
		FALSE
	);
	NTSTATUS status = WdfDeviceInitAssignName(
		deviceInit,
		&deviceName
	);
	if (!NT_SUCCESS(status)) {
		DbgPrint("WdfDeviceInitAssignName failed with status %d\n", status);
		return NULL;
	}
	WDFDEVICE device;
	status = WdfDeviceCreate(
		&deviceInit,
		WDF_NO_OBJECT_ATTRIBUTES,
		&device
	);
	if (!NT_SUCCESS(status)) {
		DbgPrint("WdfDeviceCreate failed with status %d\n", status);
		return NULL;
	}
	return device;
}

HANDLE createInjectionHandle() {
	HANDLE handle;
	NTSTATUS status = FwpsInjectionHandleCreate(
		AF_INET,
		FWPS_INJECTION_TYPE_NETWORK,
		&handle
	);
	if (!NT_SUCCESS(status)) {
		DbgPrint("FwpsInjectionHandleCreate failed with status %d\n", status);
		return NULL;
	}
	return handle;
}

HANDLE openFilterEngine() {
	HANDLE engineHandle;
	NTSTATUS status = FwpmEngineOpen(
		NULL,
		RPC_C_AUTHN_WINNT,
		NULL,
		NULL,
		&engineHandle
	);
	if (!NT_SUCCESS(status)) {
		DbgPrint("FwpmEngineOpen failed with status %d\n", status);
		return NULL;
	}
	return engineHandle;
}

HANDLE newNetBufferListPool() {
	NET_BUFFER_LIST_POOL_PARAMETERS params = { 0 };
	params.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
	params.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
	params.Header.Size = sizeof(NET_BUFFER_LIST_POOL_PARAMETERS);
	params.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
	params.fAllocateNetBuffer = TRUE; // the netBufferList starts with one netBuffer.
	params.DataSize = 0;			  // must be set to 0 to use FwpsAllocateNetBufferAndNetBufferList.
	params.PoolTag = ((ULONG)'YYYY');
	HANDLE poolHandle = NdisAllocateNetBufferListPool(NULL, &params);
	if (poolHandle == NULL) {
		DbgPrint("NdisAllocateNetBufferListPool returned NULL\n");
		return NULL;
	}
	return poolHandle;
}

UINT32 addCallout(
	WDFDEVICE device,
	HANDLE filterEngine,
	GUID calloutKey,
	FWPS_CALLOUT_CLASSIFY_FN3 classifyFn,
	FWPS_CALLOUT_NOTIFY_FN3 notifyFn,
	wchar_t* displayName,
	GUID applicableLayer
) {
	UINT32 id;

	// Step 1: Register the callout with the filter engine.
	FWPS_CALLOUT fwps_callout = {
		calloutKey,
		0,
		classifyFn,
		notifyFn,
		NULL
	};
	NTSTATUS status = FwpsCalloutRegister(
		WdfDeviceWdmGetDeviceObject(device),
		&fwps_callout,
		&id
	);
	if (!NT_SUCCESS(status)) {
		DbgPrint("FwpsCalloutRegister failed with status %d\n", status);
		return 0;
	}

	// Step 2: Add the callout to the system.
	FWPM_CALLOUT fwpm_callout = { 0 };
	fwpm_callout.calloutKey = calloutKey;
	fwpm_callout.displayData.name = displayName;
	fwpm_callout.applicableLayer = applicableLayer;
	status = FwpmCalloutAdd(
		filterEngine,
		&fwpm_callout,
		NULL,
		NULL
	);
	if (!NT_SUCCESS(status)) {
		DbgPrint("FwpmCalloutAdd failed with status %d\n", status);
		return 0;
	}
	return id;
}

NET_BUFFER_LIST* newNetBufferList(HANDLE pool, ULONG size) {
	NET_BUFFER_LIST* netBufferList = NULL;
	NTSTATUS status = FwpsAllocateNetBufferAndNetBufferList(
		pool,
		0,
		0,
		NULL,
		0,
		size, // used for netBuffer->DataLength (total data length)
		&netBufferList
	);
	if (!NT_SUCCESS(status)) {
		DbgPrint("FwpsAllocateNetBufferAndNetBufferList failed with status %d\n", status);
		return NULL;
	}
	// Allocate non-pageable memory and describe it with MDL.
	VOID* mem = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, ((ULONG)'YYYY'));
	if (mem == NULL) {
		DbgPrint("ExAllocatePool2 returned NULL\n");
		return NULL;
	}
	MDL* outputMdl = IoAllocateMdl(
		mem,
		size, // size of this mdl (which, in this case, is just the total data length)
		FALSE,
		FALSE,
		NULL
	);
	if (outputMdl == NULL) {
		DbgPrint("IoAllocateMdl returned NULL\n");
		return NULL;
	}
	MmBuildMdlForNonPagedPool(outputMdl);
	NET_BUFFER* outputNetBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
	outputNetBuffer->CurrentMdl = outputMdl;
	outputNetBuffer->MdlChain = outputMdl;
	return netBufferList;
}

void* getBuffer(NET_BUFFER_LIST* netBufferList, void* storage) {
	NET_BUFFER* netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
	void* buffer = NdisGetDataBuffer(netBuffer, netBuffer->DataLength, storage, 1, 0);
	if (buffer == NULL) {
		DbgPrint("NdisGetDataBuffer returned NULL\n");
		return NULL;
	}
	return buffer;
}

ULONG getBufferSize(NET_BUFFER_LIST* netBufferList) {
	NET_BUFFER* netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
	return netBuffer->DataLength;
}