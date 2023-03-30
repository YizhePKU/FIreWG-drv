#include "callout.h"
#include "utils.h"

NTSTATUS NTAPI
notifyFn(
	FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	const GUID* filterKey,
	const FWPS_FILTER* filter
) {
	DbgPrint("notifyFn entry\n");

	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);

	return STATUS_SUCCESS;
}

void NTAPI
aleInboundClassifyFn(
	const FWPS_INCOMING_VALUES* inFixedValues,
	const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	void* layerData,
	const void* classifyContext,
	const FWPS_FILTER* filter,
	UINT64 flowContext,
	FWPS_CLASSIFY_OUT* classifyOut
) {
	UNREFERENCED_PARAMETER(inFixedValues);
	UNREFERENCED_PARAMETER(inMetaValues);
	UNREFERENCED_PARAMETER(layerData);
	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(flowContext);
	UNREFERENCED_PARAMETER(classifyOut);

	// Allow self-injected packets.
	FWPS_PACKET_INJECTION_STATE state = FwpsQueryPacketInjectionState(
		injectionHandle,
		layerData,
		NULL
	);
	if (state == FWPS_PACKET_INJECTED_BY_SELF || state == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF) {
		DbgPrint("aleInboundClassifyFn permitted self-injected packet\n");
		classifyOut->actionType = FWP_ACTION_PERMIT;
		return;
	}

	// Block all inbound traffic for tracked APPs (because they didn't go though Wireguard).
	// TODO: Allow APPs to listen on port (passive open).
	FWP_VALUE appId = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_APP_ID].value;
	if (rsIsAppTracked(appId.byteBlob->data, appId.byteBlob->size)) {
		DbgPrint("aleInboundClassifyFn blocked direct inbound packet\n");
		classifyOut->actionType = FWP_ACTION_BLOCK;
	}
	else {
		classifyOut->actionType = FWP_ACTION_PERMIT;
	}
}

void NTAPI
aleOutboundClassifyFn(
	const FWPS_INCOMING_VALUES* inFixedValues,
	const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	void* layerData,
	const void* classifyContext,
	const FWPS_FILTER* filter,
	UINT64 flowContext,
	FWPS_CLASSIFY_OUT* classifyOut
) {
	UNREFERENCED_PARAMETER(inFixedValues);
	UNREFERENCED_PARAMETER(inMetaValues);
	UNREFERENCED_PARAMETER(layerData);
	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(flowContext);
	UNREFERENCED_PARAMETER(classifyOut);

	// Send (appId, protocol, localAddress, localPort, remoteAddress, remotePort) to Rust.
	FWP_VALUE appId = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_APP_ID].value;
	FWP_VALUE protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value;
	FWP_VALUE localAddress = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value;
	FWP_VALUE localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value;
	FWP_VALUE remoteAddress = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value;
	FWP_VALUE remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value;
	rsRegisterConnection(
		appId.byteBlob->data,
		appId.byteBlob->size,
		protocol.uint8,
		localAddress.uint32,
		localPort.uint16,
		remoteAddress.uint32,
		remotePort.uint16
	);

	classifyOut->actionType = FWP_ACTION_PERMIT;
}

void NTAPI
ipInboundClassifyFn(
	const FWPS_INCOMING_VALUES* inFixedValues,
	const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	void* layerData,
	const void* classifyContext,
	const FWPS_FILTER* filter,
	UINT64 flowContext,
	FWPS_CLASSIFY_OUT* classifyOut
) {
	UNREFERENCED_PARAMETER(inFixedValues);
	UNREFERENCED_PARAMETER(inMetaValues);
	UNREFERENCED_PARAMETER(layerData);
	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(flowContext);
	UNREFERENCED_PARAMETER(classifyOut);

	// Allow self-injected packets.
	FWPS_PACKET_INJECTION_STATE state = FwpsQueryPacketInjectionState(
		injectionHandle,
		layerData,
		NULL
	);
	if (state == FWPS_PACKET_INJECTED_BY_SELF || state == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF) {
		DbgPrint("ipInboundClassifyFn permitted self-injected packet\n");
		classifyOut->actionType = FWP_ACTION_PERMIT;
		return;
	}

	rsHandleInboundPacket(
		getBuffer(layerData),
		getBufferSize(layerData)
	);
}

void NTAPI
ipOutboundClassifyFn(
	const FWPS_INCOMING_VALUES* inFixedValues,
	const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	void* layerData,
	const void* classifyContext,
	const FWPS_FILTER* filter,
	UINT64 flowContext,
	FWPS_CLASSIFY_OUT* classifyOut
) {
	DbgPrint("ipOutboundClassifyFn entry\n");

	UNREFERENCED_PARAMETER(inFixedValues);
	UNREFERENCED_PARAMETER(inMetaValues);
	UNREFERENCED_PARAMETER(layerData);
	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(flowContext);
	UNREFERENCED_PARAMETER(classifyOut);

	// Allow self-injected packets.
	FWPS_PACKET_INJECTION_STATE state = FwpsQueryPacketInjectionState(
		injectionHandle,
		layerData,
		NULL
	);
	if (state == FWPS_PACKET_INJECTED_BY_SELF || state == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF) {
		DbgPrint("ipOutboundClassifyFn permitted self-injected packet\n");
		classifyOut->actionType = FWP_ACTION_PERMIT;
		return;
	}

	rsHandleOutboundPacket(
		getBuffer(layerData),
		getBufferSize(layerData)
	);
}