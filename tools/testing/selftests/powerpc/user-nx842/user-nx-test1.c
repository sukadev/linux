#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include "nx.h"
#include "nx-helpers.h"

void *fault_storage_address;

void sigsegv_handler(int sig, siginfo_t *info, void *ctx)
{
	printf("%d: Got signal %d si_code %d, si_addr %p\n", getpid(),
		sig, info->si_code, info->si_addr);

	fault_storage_address = info->si_addr;
}

int main(int argc, char *argv[])
{
	int i, rc, crc, len, align;
	void *handle;
	nxbuf_t in, comp, out;
	struct nx842_func_args nxargs;
	struct sigaction act;

	crc = 1;
	len = 64 << 10;
	align = 256;

	if (argc > 1)
		len = atoi(argv[1]) * 1024;

	if (argc > 2)
		crc = atoi(argv[2]);

	if (argc > 3)
		align = atoi(argv[3]);

	printf("user-nx-test1: Test Info:\n");
	printf("842: Compress/decompress data and compare results\n");
	printf("\t Page size %ld\n", sysconf(_SC_PAGESIZE));
	printf("\t Buffer size %d\n", len);
	printf("\t Buffer Align %d\n", align);
	printf("\t CRC %s\n", crc ? "Enabled" : "Disabled");

	act.sa_handler = 0;
	act.sa_sigaction = sigsegv_handler;
	act.sa_flags = SA_SIGINFO;
	act.sa_restorer = 0;
	sigemptyset(&act.sa_mask);

	sigaction(SIGSEGV, &act, NULL);

	memset(&nxargs, 0, sizeof(nxargs));
	nxargs.use_crc = crc;
	nxargs.timeout = 3;

	in.len = len;
	in.buf = alloc_aligned_mem(in.len, align, "Input data");
	if (!in.buf) {
		printf("Unable to alloc %d bytes for input\n", in.len);
		_Exit(1);
	}

	out.len = len;
	out.buf = alloc_aligned_mem(out.len, align, "Output data");
	if (!out.buf) {
		printf("Unable to alloc %d bytes for output\n", out.len);
		_Exit(1);
	}

	comp.len = len;
	comp.buf = alloc_aligned_mem(comp.len, align, "Compressed data");
	if (!comp.buf) {
		printf("Unable to alloc %d bytes for output\n", comp.len);
		_Exit(1);
	}

	get_payload(in.buf, in.len);

	handle = nx_function_begin(NX_FUNC_COMP_842, 0);
	if (!handle) {
		printf("Unable to init NX, errno %d\n", errno);
		_Exit(1);
	}

	rc = nx_function(handle, &in, &comp, &nxargs);
	if (rc) {
		printf("nx_function returns %d, errno %d\n", rc, errno);
		_Exit(1);
	}

	nxargs.decompress = 1;
	rc = nx_function(handle, &comp, &out, &nxargs);
	if (rc) {
		printf("nx_function returns %d, errno %d\n", rc, errno);
		_Exit(1);
	}

	printf("Input len %d, Compressed len %d, output len %d\n",
			in.len, comp.len, out.len);
	len = in.len;
	if (in.len != out.len) {
		printf("Input len %d, output len %d, mismatch!!\n",
				in.len, out.len);
		len = min_t(int, in.len, out.len);
	}

	for (i = 0; i < len; i++) {
		if (in.buf[i] != out.buf[i]) {
			printf("Input and output buffers MISMATCH at %d\n", i);
			break;
		}
	}
	if (i == len)
		printf("Input and output data match\n");

	dump_buffer("Input data", in.buf, in.len);
	dump_buffer("Compressed data", comp.buf, comp.len);
	dump_buffer("Output data", out.buf, out.len);

	nx_function_end(handle);
}
