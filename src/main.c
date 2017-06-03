#include <stdlib.h>
#include <string.h>

#include <debug.h>
#include <device.h>
#include <io.h>
#include <status.h>

static struct io_interface *ioif;

int main(int argc, char *argv[])
{
	int fd = -1;
	int ret = STATUS_EXEC_ERROR;

	printf("ATSHA204A on %s @ addr 0x%x\n", I2C_DEVICE, ATSHA204A_ADDR);

	ret = register_io_interface(IO_I2C_LINUX, &ioif);
	if (ret != STATUS_OK) {
	    logd("Couldn't register the IO interface\n");
	    goto out;
	}

	ret = at204_open(ioif);

	//while (!cmd_wake(ioif)) {};
	cmd_wake(ioif);
	printf("ATSHA204A is awake\n");

	// cmd_get_random(ioif);
	cmd_devrev(ioif);
	printf("\n - Nonce -\n");
	get_nonce(ioif);
#if 0
	cmd_get_serialnbr(ioif);
	cmd_get_otp_mode(ioif);

	{
		int i;
		for (i = 0; i < 16; i++)
			cmd_get_slot_config(ioif, i);
	}

	cmd_get_lock_data(ioif);
	cmd_get_lock_config(ioif);
#endif

	ret = at204_close(ioif);
	if (ret != STATUS_OK) {
		ret = STATUS_EXEC_ERROR;
		logd("Couldn't close the device\n");
	}
out:
	return ret;
}
