#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cmd.h>
#include <crc_local.h>
#include <debug.h>
#include <packet.h>
#include <status.h>

/*
 * This serializes a command packet. It will also calculate and store the
 * checksum for the package.
 */
void get_command(struct cmd_packet *p, uint8_t opcode)
{
	assert(p);

	p->count = 0;
	p->command = PKT_FUNC_COMMAND;
	p->opcode = opcode;
	p->data = NULL;
	p->data_length = 0;

	switch (p->opcode)
	{
	case OPCODE_DERIVEKEY:
		break;
	case OPCODE_DEVREV:
		p->count = 0;
		p->param1 = 0;
		p->param2[0] = 0;
		p->param2[1] = 0;
		p->data = NULL;
		p->data_length = 0;
		p->max_time = 2; /* Table 8.4 */
		break;
	case OPCODE_GENDIG:
		break;
	case OPCODE_HMAC:
		break;
	case OPCODE_CHECKMAC:
		break;
	case OPCODE_LOCK:
		break;
	case OPCODE_MAC:
		break;
	case OPCODE_NONCE:
		p->count = 0;
		p->param2[0] = 0x00;
		p->param2[1] = 0x00;
		p->max_time = 60; /* Table 8.4 */
		break;
	case OPCODE_PAUSE:
		break;

	case OPCODE_RANDOM:
		p->count = 0;
		p->param1 = 0;
		p->param2[0] = 0x00;
		p->param2[1] = 0x00;
		p->data = NULL;
		p->data_length = 0;
		p->max_time = 50; /* Table 8.4 */
		break;

	case OPCODE_READ:
		p->count = 0;
		p->data = NULL;
		p->data_length = 0;
		p->max_time = 4; /* Table 8.4 */
		break;
	case OPCODE_SHA:
		break;
	case OPCODE_UPDATEEXTRA:
		break;
	case OPCODE_WRITE:
		p->max_time = 42;
		break;

	default:
		break;
	}
}

bool cmd_wake(struct io_interface *ioif)
{
	int ret = STATUS_EXEC_ERROR;
	ssize_t n = 0;
	uint8_t cmd = CMD_WAKEUP;
	uint8_t buf;

	n = at204_write(ioif, &cmd, sizeof(cmd));
	if (n <= 0)
		return false;

	ret = at204_read(ioif, &buf, sizeof(buf));
	return ret == STATUS_OK || ret == STATUS_AFTER_WAKE;
}

int cmd_read(struct io_interface *ioif, uint8_t zone, uint8_t addr,
	     uint8_t offset, size_t size, void *data, size_t data_size)
{
	int ret = STATUS_EXEC_ERROR;
	struct cmd_packet p;
	uint8_t resp_buf[size];

	assert(zone < ZONE_END);
	assert(size == 4 || size == 32);

	get_command(&p, OPCODE_READ);

	/*
	 * Bit 7 should be '1' for 32 byte reads and always zero, when zone is
	 * OTP (see Table 8-33 in the specification).
	 */
	if (zone == ZONE_OTP)
		zone &= ~(1 << 7);
	else if (data_size == 32)
		zone &= (1 << 7);

	p.param1 = zone;
	p.param2[0] = addr;
	p.param2[1] = 0;

	ret = at204_msg(ioif, &p, resp_buf, sizeof(resp_buf));

	if (ret == STATUS_OK)
		memcpy(data, &resp_buf[offset], data_size);
	else
		loge("Failed to read from config zone!\n");

	return ret;
}

int cmd_get_devrev(struct io_interface *ioif, uint8_t *buf, size_t size)
{
	int ret = STATUS_EXEC_ERROR;
	struct cmd_packet p;

	if (size != DEVREV_LEN || !buf)
		return STATUS_BAD_PARAMETERS;

	get_command(&p, OPCODE_DEVREV);

	return at204_msg(ioif, &p, buf, size);
}

int cmd_get_lock_config(struct io_interface *ioif, uint8_t *lock_config)
{
	uint8_t _lock_config = 0;
	int ret = STATUS_EXEC_ERROR; 

	ret = cmd_read(ioif, ZONE_CONFIG, LOCK_CONFIG_ADDR, LOCK_CONFIG_OFFSET,
		       WORD_SIZE, &_lock_config, LOCK_CONFIG_SIZE);

	if (ret == STATUS_OK)
		*lock_config = _lock_config;
	else
		*lock_config = 0;

	return ret;
}

int cmd_get_lock_data(struct io_interface *ioif, uint8_t *lock_data)
{
	uint8_t _lock_data = 0;
	int ret = STATUS_EXEC_ERROR;

	ret = cmd_read(ioif, ZONE_CONFIG, LOCK_DATA_ADDR, LOCK_DATA_OFFSET,
		       WORD_SIZE, &_lock_data, LOCK_DATA_SIZE);

	if (ret == STATUS_OK)
		*lock_data = _lock_data;
	else
		*lock_data = 0;

	return ret;
}

int cmd_get_nonce(struct io_interface *ioif, uint8_t *in, size_t in_size,
		  uint8_t mode, uint8_t *out, size_t out_size)
{
	int ret = STATUS_EXEC_ERROR;
	struct cmd_packet p;

	if (!in ||
	    (in_size != NONCE_SHORT_NUMIN && in_size != NONCE_LONG_NUMIN) ||
	    !out || (out_size != NONCE_SHORT_LEN && out_size != NONCE_LONG_LEN))
		return STATUS_BAD_PARAMETERS;

	if (mode != NONCE_MODE_UPDATE_SEED && mode != NONCE_MODE_NO_SEED &&
	     mode != NONCE_MODE_PASSTHROUGH)
		return STATUS_BAD_PARAMETERS;

	if (in_size == NONCE_LONG_NUMIN && mode != NONCE_MODE_PASSTHROUGH)
		return STATUS_BAD_PARAMETERS;

	get_command(&p, OPCODE_NONCE);

	p.param1 = mode;
	p.data = in;
	p.data_length = in_size;

	ret = at204_msg(ioif, &p, out, out_size);

	if (ret != STATUS_OK)
		memset(out, 0, out_size);

	return ret;
}

int cmd_get_otp_mode(struct io_interface *ioif, uint8_t *otp_mode)
{
	uint32_t _otp_mode = 0;
	int ret = STATUS_EXEC_ERROR;

	if (!otp_mode)
		return ret;

	ret = cmd_read(ioif, ZONE_CONFIG, OTP_CONFIG_ADDR, OTP_CONFIG_OFFSET,
		       WORD_SIZE, &_otp_mode, OTP_CONFIG_SIZE);

	*otp_mode = _otp_mode & 0xFF;

#if DEBUG
	switch(*otp_mode) {
	case 0xAA:
		logd(" (OTP: Read only mode)\n");
		break;
	case 0x55:
		logd(" (OTP: Consumption mode)\n");
		break;
	case 0x00:
		logd(" (OTP: Legacy mode)\n");
		break;
	default:
		logd(" (OTP: Unknown mode)\n");
	}
#endif

	return ret;
}

int cmd_get_random(struct io_interface *ioif, uint8_t *buf, size_t size)
{
	int ret = STATUS_EXEC_ERROR;
	struct cmd_packet p;

	/*
	 * ATSHA204A will always need to return the result from RANDOM in a 32
	 * byte buffer, so always make this check.
	 */
	if (size != RANDOM_LEN || !buf)
		return STATUS_BAD_PARAMETERS;

	get_command(&p, OPCODE_RANDOM);

	return at204_msg(ioif, &p, buf, size);
}

int cmd_get_serialnbr(struct io_interface *ioif, uint8_t *buf, size_t size)
{
	/* Only 9 are used, but we read 4 bytes at a time */
	uint8_t serial_nbr[12] = { 0 };
	int ret = STATUS_EXEC_ERROR;

	if (size != SERIALNUM_LEN || !buf)
		return STATUS_BAD_PARAMETERS;

	ret = cmd_read(ioif, ZONE_CONFIG, SERIALNBR_ADDR0_3,
		       SERIALNBR_OFFSET0_3, WORD_SIZE, serial_nbr,
		       SERIALNBR_SIZE0_3);
	if (ret != STATUS_OK)
		goto err;

	ret = cmd_read(ioif, ZONE_CONFIG, SERIALNBR_ADDR4_7,
		       SERIALNBR_OFFSET4_7, WORD_SIZE, serial_nbr +
		       SERIALNBR_SIZE0_3, SERIALNBR_SIZE4_7);
	if (ret != STATUS_OK)
		goto err;

	ret = cmd_read(ioif, ZONE_CONFIG, SERIALNBR_ADDR8, SERIALNBR_OFFSET8,
		       WORD_SIZE, serial_nbr + SERIALNBR_SIZE4_7,
		       SERIALNBR_SIZE8);
err:
	if (ret == STATUS_OK)
		memcpy(buf, serial_nbr, size);
	else
		memset(buf, 0, size);

	return ret;
}

int cmd_get_slot_config(struct io_interface *ioif, uint8_t slotnbr,
			uint16_t *slot_config)
{
	uint32_t _slot_config;
	int ret = STATUS_EXEC_ERROR;

	logd("slotnbr: %d, addr: 0x%02x, offset: %d\n", slotnbr,
	     SLOT_CONFIG_ADDR(slotnbr), SLOT_CONFIG_OFFSET(slotnbr));

	ret = cmd_read(ioif, ZONE_CONFIG, SLOT_CONFIG_ADDR(slotnbr),
		       SLOT_CONFIG_OFFSET(slotnbr), WORD_SIZE, &_slot_config,
		       SLOT_CONFIG_SIZE);
	if (ret == STATUS_OK)
		*slot_config = _slot_config & 0xFFFF;
	else
		*slot_config = 0;

	return ret;
}

int cmd_write(struct io_interface *ioif, uint8_t zone, uint8_t addr,
	       uint8_t *data, size_t size)
{
	ssize_t n = 0;
	struct cmd_packet p;
	int ret = STATUS_EXEC_ERROR;

	get_command(&p, OPCODE_WRITE);
	p.param1 = zone;
	p.param2[0] = addr;
	p.data = data;
	p.data_length = size;

#if 0
	if (size != 0 && size != 4 && size != 32) {
		loge("Wrong size when trying to write\n");
		goto err;
	}
#endif

	n = at204_write2(ioif, &p);
	logd("cmd_write: wrote %d bytes\n", n);
err:
	return ret;
}
