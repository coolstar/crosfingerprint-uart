#pragma warning(disable:4200)  // suppress nameless struct/union warning
#pragma warning(disable:4201)  // suppress nameless struct/union warning
#pragma warning(disable:4214)  // suppress bit field types other than int warning
#include <initguid.h>
#include <wdm.h>

#pragma warning(default:4200)
#pragma warning(default:4201)
#pragma warning(default:4214)
#include <wdf.h>

#include "crosfingerprint.h"
#include "ec_commands.h"

static ULONG CrosFPDebugLevel = 100;
static ULONG CrosFPDebugCatagories = DBG_INIT || DBG_PNP || DBG_IOCTL;

NTSTATUS cros_ec_pkt_xfer(
	PCROSFP_CONTEXT pDevice,
	PCROSEC_COMMAND msg
) {
	NTSTATUS status;

	unsigned int dout_len = sizeof(struct ec_host_request) + msg->OutSize;
	unsigned int din_len = sizeof(struct ec_host_response) + msg->InSize;

	UINT8* dout = ExAllocatePoolWithTag(NonPagedPool, dout_len, CROSFP_POOL_TAG);
	UINT8* din = ExAllocatePoolWithTag(NonPagedPool, din_len, CROSFP_POOL_TAG);
	if (!dout || !din) {
		status = STATUS_NO_MEMORY;
		goto out;
	}

	RtlZeroMemory(dout, dout_len);
	RtlZeroMemory(din, din_len);

	{ //prepare packet
		struct ec_host_request *request = (struct ec_host_request *)dout;
		request->struct_version = EC_HOST_REQUEST_VERSION;
		request->checksum = 0;
		request->command = msg->Command;
		request->command_version = msg->Version;
		request->reserved = 0;
		request->data_len = msg->OutSize;

		UINT8 csum = 0;
		for (int i = 0; i < sizeof(*request); i++) {
			csum += dout[i];
		}

		/* Copy data and update checksum */
		memcpy(dout + sizeof(*request), msg->Data, msg->OutSize);
		for (int i = 0; i < msg->OutSize; i++)
			csum += msg->Data[i];

		request->checksum = -csum;
	}

	status = UartWrite(&pDevice->UartContext, dout, dout_len);
	if (!NT_SUCCESS(status)) {
		CrosFPPrint(
			DEBUG_LEVEL_ERROR,
			DBG_IOCTL,
			"Error writing to UART: %x\n", status);
		goto out;
	}

	LARGE_INTEGER Interval;
	Interval.QuadPart = -10 * 1000 * 500;
	KeDelayExecutionThread(KernelMode, false, &Interval);

	status = UartRead(&pDevice->UartContext, din, din_len);
	if (!NT_SUCCESS(status)) {
		CrosFPPrint(
			DEBUG_LEVEL_ERROR,
			DBG_IOCTL,
			"Error reading from UART: %x\n", status);
		goto out;
	}

	struct ec_host_response *response = (struct ec_host_response *)din;
	msg->Result = response->result;

	if (response->data_len > msg->InSize) {
		CrosFPPrint(
			DEBUG_LEVEL_ERROR,
			DBG_IOCTL,
			"Resp too long (%d bytes, expected %d)\n", response->data_len, msg->InSize);
		status = STATUS_BUFFER_OVERFLOW;
		goto out;
	}

	/* Copy response packet to ec_msg data buffer */
	memcpy(msg->Data,
		din + sizeof(*response),
		response->data_len);

	UINT8 sum = 0;
	/* Add all response header bytes for checksum calculation */
	for (int i = 0; i < sizeof(*response); i++)
		sum += din[i];

	/* Copy response packet payload and compute checksum */
	for (int i = 0; i < response->data_len; i++)
		sum += msg->Data[i];

	if (sum) {
		CrosFPPrint(
			DEBUG_LEVEL_ERROR,
			DBG_IOCTL,
			"Bad packet checksum calculated %x\n",
			sum);
		status = STATUS_DATA_CHECKSUM_ERROR;
	}

	status = STATUS_SUCCESS;

out:
	if (dout) {
		ExFreePoolWithTag(dout, CROSFP_POOL_TAG);
	}

	if (din) {
		ExFreePoolWithTag(din, CROSFP_POOL_TAG);
	}

	return status;
}

NTSTATUS cros_ec_command (
	PCROSFP_CONTEXT pDevice,
	int command, int version,
	const void* outdata, int outsize,
	void* indata, int insize
) {
	PCROSEC_COMMAND msg = ExAllocatePoolWithTag(NonPagedPool, sizeof(CROSEC_COMMAND) + max(insize, outsize), CROSFP_POOL_TAG);
	if (!msg) {
		return STATUS_NO_MEMORY;
	}

	msg->Command = command;
	msg->Version = version;
	msg->OutSize = outsize;
	msg->InSize = insize;

	memcpy(msg->Data, outdata, outsize);
	
	NTSTATUS status = cros_ec_pkt_xfer(pDevice, msg);

	memcpy(indata, msg->Data, insize);

	ExFreePoolWithTag(msg, CROSFP_POOL_TAG);

	return status;
}

/**
 * Get the versions of the command supported by the EC.
 *
 * @param cmd		Command
 * @param pmask		Destination for version mask; will be set to 0 on
 *			error.
 */
static NTSTATUS cros_ec_get_cmd_versions(PCROSFP_CONTEXT pDevice, int cmd, UINT32* pmask) {
	struct ec_params_get_cmd_versions_v1 pver_v1;
	struct ec_params_get_cmd_versions pver;
	struct ec_response_get_cmd_versions rver;
	NTSTATUS status;

	*pmask = 0;

	pver_v1.cmd = cmd;
	status = cros_ec_command(pDevice, EC_CMD_GET_CMD_VERSIONS, 1, &pver_v1, sizeof(pver_v1),
		&rver, sizeof(rver));

	if (!NT_SUCCESS(status)) {
		pver.cmd = cmd;
		status = cros_ec_command(pDevice, EC_CMD_GET_CMD_VERSIONS, 0, &pver, sizeof(pver),
			&rver, sizeof(rver));
	}

	*pmask = rver.version_mask;
	return status;
}

/**
 * Return non-zero if the EC supports the command and version
 *
 * @param cmd		Command to check
 * @param ver		Version to check
 * @return non-zero if command version supported; 0 if not.
 */
BOOLEAN cros_ec_cmd_version_supported(PCROSFP_CONTEXT pDevice, int cmd, int ver)
{
	uint32_t mask = 0;

	if (NT_SUCCESS(cros_ec_get_cmd_versions(pDevice, cmd, &mask)))
		return false;

	return (mask & EC_VER_MASK(ver)) ? true : false;
}