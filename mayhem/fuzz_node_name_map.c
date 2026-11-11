/* Fuzzes the node-name-map file parser shared by the infiniband-diags tools
 * (open_node_name_map / remap_node_name / clean_nodedesc). The input is the map file. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <util/node_name_map.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const char *dir = getenv("TMPDIR");
	char path[512];
	char desc[65];
	nn_map_t *map;
	size_t off = 0;
	uint64_t guid = 0;
	char *name;
	int fd, i;

	if (!dir || !*dir)
		dir = "/tmp";
	snprintf(path, sizeof(path), "%s/nnmap-XXXXXX", dir);
	fd = mkstemp(path);
	if (fd < 0)
		abort();
	while (off < size) {
		ssize_t n = write(fd, data + off, size - off);
		if (n <= 0)
			abort();
		off += n;
	}
	close(fd);

	map = open_node_name_map(path);
	unlink(path);
	if (!map)
		return 0;

	/* node descriptions are fixed 64-byte SMP fields (IB_SMP_DATA_SIZE) */
	memset(desc, 0, sizeof(desc));
	memcpy(desc, data, size < 64 ? size : 64);
	for (i = 0; i < 4; i++) {
		if (size >= 8 * (size_t)(i + 1))
			memcpy(&guid, data + 8 * i, 8);
		name = remap_node_name(map, guid, desc);
		free(name);
	}
	close_node_name_map(map);
	return 0;
}
