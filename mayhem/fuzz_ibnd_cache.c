/* Fuzzes the ibnetdiscover fabric-cache loader (ibnd_load_fabric) and, for accepted
 * caches, the consumers ibnetdiscover/ibcacheedit run next: node/port walks, LID and
 * GUID lookups and a re-cache + reload round trip. The input is the cache file. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <infiniband/ibnetdisc.h>

static int scratch(char *path, size_t len)
{
	const char *dir = getenv("TMPDIR");

	if (!dir || !*dir)
		dir = "/tmp";
	snprintf(path, len, "%s/ibnd-cache-XXXXXX", dir);
	return mkstemp(path);
}

static void visit_port(ibnd_port_t *port, void *data)
{
	unsigned long *acc = data;

	*acc += port->guid + port->base_lid + (unsigned)port->portnum;
	if (port->node)
		*acc += port->node->guid;
	if (port->remoteport && port->remoteport->node)
		*acc += port->remoteport->node->guid + port->remoteport->portnum;
}

static void visit_node(ibnd_node_t *node, void *data)
{
	unsigned long *acc = data;
	int i;

	*acc += node->guid + strlen(node->nodedesc);
	if (node->ports)
		for (i = 0; i <= node->numports; i++)
			if (node->ports[i])
				visit_port(node->ports[i], data);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char path[512], path2[512];
	unsigned long acc = 0;
	ibnd_fabric_t *fabric, *again;
	size_t off = 0;
	int fd, fd2;

	fd = scratch(path, sizeof(path));
	if (fd < 0)
		abort();
	while (off < size) {
		ssize_t n = write(fd, data + off, size - off);
		if (n <= 0)
			abort();
		off += n;
	}
	close(fd);

	fabric = ibnd_load_fabric(path, 0);
	unlink(path);
	if (!fabric)
		return 0;

	ibnd_iter_nodes(fabric, visit_node, &acc);
	ibnd_iter_ports(fabric, visit_port, &acc);
	if (fabric->from_node) {
		ibnd_find_node_guid(fabric, fabric->from_node->guid);
		if (fabric->from_node->ports && fabric->from_node->numports >= 1 &&
		    fabric->from_node->ports[1])
			ibnd_find_port_lid(fabric, fabric->from_node->ports[1]->base_lid);
	}

	fd2 = scratch(path2, sizeof(path2));
	if (fd2 < 0)
		abort();
	close(fd2);
	if (ibnd_cache_fabric(fabric, path2, IBND_CACHE_FABRIC_FLAG_DEFAULT) == 0) {
		again = ibnd_load_fabric(path2, 0);
		if (again)
			ibnd_destroy_fabric(again);
	}
	unlink(path2);

	ibnd_destroy_fabric(fabric);
	return acc == 0xdeadbeefcafeUL ? -1 : 0;
}
