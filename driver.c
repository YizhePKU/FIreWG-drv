#include "callout.h"
#include "utils.h"

// {86C4F5AB-2EB6-4416-95DC-4D47D716F359}
static const GUID ALE_INBOUND_CALLOUT_KEY =
{ 0x86c4f5ab, 0x2eb6, 0x4416, { 0x95, 0xdc, 0x4d, 0x47, 0xd7, 0x16, 0xf3, 0x59 } };

// {58D2A0C5-5EBD-4179-B36C-2E670ED8035E}
static const GUID ALE_OUTBOUND_CALLOUT_KEY =
{ 0x58d2a0c5, 0x5ebd, 0x4179, { 0xb3, 0x6c, 0x2e, 0x67, 0xe, 0xd8, 0x3, 0x5e } };

// {B03B57AA-F559-4FA4-8E1D-ACC187807299}
static const GUID IP_INBOUND_CALLOUT_KEY =
{ 0xb03b57aa, 0xf559, 0x4fa4, { 0x8e, 0x1d, 0xac, 0xc1, 0x87, 0x80, 0x72, 0x99 } };

// {B34277B9-7E88-4119-BAC2-F8B71A0F86DA}
static const GUID IP_OUTBOUND_CALLOUT_KEY =
{ 0xb34277b9, 0x7e88, 0x4119, { 0xba, 0xc2, 0xf8, 0xb7, 0x1a, 0xf, 0x86, 0xda } };

HANDLE injectionHandle;
HANDLE netBufferListPool;

UINT64 aleInboundFilterId;
UINT64 aleOutboundFilterId;
UINT64 ipInboundFilterId;
UINT64 ipOutboundFilterId;

void driverUnload(WDFDRIVER Driver) {
	UNREFERENCED_PARAMETER(Driver);
}

NTSTATUS
DriverEntry(
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath
) {
	DbgPrint("DriverEntry entry\n");

	WDFDRIVER driver = createDriver(DriverObject, RegistryPath, driverUnload);
	if (driver == NULL)
		return -1;

	DECLARE_CONST_UNICODE_STRING(DeviceName, L"\\Device\\FireWG-Device");
	WDFDEVICE device = createDevice(driver, DeviceName);
	if (device == NULL)
		return -1;

	HANDLE filterEngine = openFilterEngine();
	if (filterEngine == NULL)
		return -1;

	injectionHandle = createInjectionHandle();
	if (injectionHandle == NULL)
		return -1;

	netBufferListPool = newNetBufferListPool();
	if (netBufferListPool == NULL)
		return -1;

	// Add callouts.
	UINT64 calloutId;
	calloutId = addCallout(
		device,
		filterEngine,
		ALE_INBOUND_CALLOUT_KEY,
		aleInboundClassifyFn,
		notifyFn,
		L"FireWG ALE Inbound Callout",
		FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
	);
	if (calloutId == 0)
		return -1;

	calloutId = addCallout(
		device,
		filterEngine,
		ALE_OUTBOUND_CALLOUT_KEY,
		aleOutboundClassifyFn,
		notifyFn,
		L"FireWG ALE Outbound Callout",
		FWPM_LAYER_ALE_AUTH_CONNECT_V4
	);
	if (calloutId == 0)
		return -1;

	calloutId = addCallout(
		device,
		filterEngine,
		IP_INBOUND_CALLOUT_KEY,
		ipInboundClassifyFn,
		notifyFn,
		L"FireWG IP Inbound Callout",
		FWPM_LAYER_INBOUND_IPPACKET_V4
	);
	if (calloutId == 0)
		return -1;

	calloutId = addCallout(
		device,
		filterEngine,
		IP_OUTBOUND_CALLOUT_KEY,
		ipOutboundClassifyFn,
		notifyFn,
		L"FireWG IP Outbound Callout",
		FWPM_LAYER_OUTBOUND_IPPACKET_V4
	);
	if (calloutId == 0)
		return -1;

	// Add filters that intercepts all packets.
	NTSTATUS status;
	FWPM_FILTER filter = { 0 };
	filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
	filter.numFilterConditions = 0;
	// ALE inbound
	filter.displayData.name = L"FireWG: filter all ALE inbound traffic";
	filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
	filter.action.calloutKey = ALE_INBOUND_CALLOUT_KEY;
	status = FwpmFilterAdd(
		filterEngine,
		&filter,
		NULL,
		&aleInboundFilterId
	);
	if (!NT_SUCCESS(status)) {
		DbgPrint("FwpmFilterAdd failed with status %d\n", status);
		return status;
	}
	// ALE outbound
	filter.displayData.name = L"FireWG: filter all ALE outbound traffic";
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
	filter.action.calloutKey = ALE_OUTBOUND_CALLOUT_KEY;
	status = FwpmFilterAdd(
		filterEngine,
		&filter,
		NULL,
		&aleOutboundFilterId
	);
	if (!NT_SUCCESS(status)) {
		DbgPrint("FwpmFilterAdd failed with status %d\n", status);
		return status;
	}
	// IP inbound
	filter.displayData.name = L"FireWG: filter all IP inbound traffic";
	filter.layerKey = FWPM_LAYER_INBOUND_IPPACKET_V4;
	filter.action.calloutKey = IP_INBOUND_CALLOUT_KEY;
	status = FwpmFilterAdd(
		filterEngine,
		&filter,
		NULL,
		&ipInboundFilterId
	);
	if (!NT_SUCCESS(status)) {
		DbgPrint("FwpmFilterAdd failed with status %d\n", status);
		return status;
	}
	// IP outbound
	filter.displayData.name = L"FireWG: filter all IP outbound traffic";
	filter.layerKey = FWPM_LAYER_OUTBOUND_IPPACKET_V4;
	filter.action.calloutKey = IP_OUTBOUND_CALLOUT_KEY;
	status = FwpmFilterAdd(
		filterEngine,
		&filter,
		NULL,
		&ipOutboundFilterId
	);
	if (!NT_SUCCESS(status)) {
		DbgPrint("FwpmFilterAdd failed with status %d\n", status);
		return status;
	}

	rsInit();

	return 0;
}