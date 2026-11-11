/* Known-answer probe for the library code the fuzz targets cover. Built with upstream's normal flags
 * (no sanitizers); prints one PASS/FAIL line per assertion. mayhem/test.sh counts them. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <infiniband/ibnetdisc.h>
#include <infiniband/mad.h>
#include <util/node_name_map.h>

static int bad;

static void check(int ok, const char *name)
{
	printf("%s: %s\n", ok ? "PASS" : "FAIL", name);
	if (!ok)
		bad++;
}

static void p16(uint8_t **p, uint16_t v) { (*p)[0] = v; (*p)[1] = v >> 8; *p += 2; }
static void p32(uint8_t **p, uint32_t v) { p16(p, v); p16(p, v >> 16); }
static void p64(uint8_t **p, uint64_t v) { p32(p, v); p32(p, v >> 32); }
static void p8(uint8_t **p, uint8_t v) { *(*p)++ = v; }
static void pbuf(uint8_t **p, const void *b, size_t n) { memcpy(*p, b, n); *p += n; }

static void put_node(uint8_t **p, uint16_t lid, uint64_t guid, uint8_t type, uint8_t nports,
		     const char *desc, uint64_t port_guid)
{
	uint8_t zero[64] = {0}, d[64] = {0};

	strncpy((char *)d, desc, sizeof(d));
	p16(p, lid); p8(p, 0); p8(p, 0);
	pbuf(p, zero, 64);
	p64(p, guid); p8(p, type); p8(p, nports);
	pbuf(p, zero, 64);
	pbuf(p, d, 64);
	p8(p, 1);
	p64(p, port_guid); p8(p, 1);
}

static void put_port(uint8_t **p, uint64_t guid, uint16_t lid, uint64_t node_guid, uint64_t rguid)
{
	uint8_t zero[64] = {0};

	p64(p, guid); p8(p, 1); p8(p, 0); p16(p, lid); p8(p, 0);
	pbuf(p, zero, 64);
	p64(p, node_guid); p8(p, 1); p64(p, rguid); p8(p, 1);
}

static void kat_cache(void)
{
	const uint64_t sw = 0x0002c90300000a01ULL, ca = 0x0002c90300000b01ULL;
	const uint64_t swp = 0x0002c90300000a02ULL, cap = 0x0002c90300000b02ULL;
	char path[] = "/tmp/kat-cache-XXXXXX", path2[] = "/tmp/kat-cache2-XXXXXX";
	uint8_t buf[2048], *p = buf;
	ibnd_fabric_t *f, *g;
	ibnd_node_t *n;
	ibnd_port_t *pt;
	int fd;

	p32(&p, 0x8FE7832B); p32(&p, 1); p32(&p, 2); p32(&p, 2); p64(&p, sw); p32(&p, 3);
	put_node(&p, 5, sw, 2, 2, "kat-switch", swp);
	put_node(&p, 9, ca, 1, 1, "kat-hca", cap);
	put_port(&p, swp, 5, sw, cap);
	put_port(&p, cap, 9, ca, swp);

	fd = mkstemp(path);
	check(fd >= 0 && write(fd, buf, p - buf) == p - buf, "cache fixture written");
	close(fd);

	f = ibnd_load_fabric(path, 0);
	check(f != NULL, "ibnd_load_fabric accepts a well-formed cache");
	if (f) {
		check(f->from_node && f->from_node->guid == sw, "from_node is the switch");
		check(f->maxhops_discovered == 3, "maxhops preserved");
		n = ibnd_find_node_guid(f, ca);
		check(n && n->numports == 1 && n->type == 1 && !strcmp(n->nodedesc, "kat-hca"),
		      "channel adapter node decoded");
		n = ibnd_find_node_guid(f, sw);
		check(n && n->numports == 2 && n->smalid == 5 && !strcmp(n->nodedesc, "kat-switch"),
		      "switch node decoded");
		pt = ibnd_find_port_lid(f, 9);
		check(pt && pt->guid == cap && pt->node && pt->node->guid == ca, "port found by LID");
		check(pt && pt->remoteport && pt->remoteport->guid == swp, "remote port link restored");
		check(n && n->ports && n->ports[1] && n->ports[1]->guid == swp, "port stored at its index");

		fd = mkstemp(path2);
		close(fd);
		check(ibnd_cache_fabric(f, path2, IBND_CACHE_FABRIC_FLAG_DEFAULT) == 0, "fabric re-cached");
		g = ibnd_load_fabric(path2, 0);
		check(g && ibnd_find_port_lid(g, 5) && ibnd_find_node_guid(g, ca), "re-cached fabric reloads");
		if (g)
			ibnd_destroy_fabric(g);
		unlink(path2);
		ibnd_destroy_fabric(f);
	}

	buf[0] ^= 0xff;
	fd = open(path, 1);
	if (fd >= 0) {
		check(write(fd, buf, 4) == 4, "magic corrupted");
		close(fd);
	}
	check(ibnd_load_fabric(path, 0) == NULL, "bad magic rejected");
	p = buf;
	p32(&p, 0x8FE7832B); p32(&p, 1); p32(&p, 1); p32(&p, 0); p64(&p, sw); p32(&p, 0);
	fd = open(path, 1);
	check(fd >= 0 && write(fd, buf, p - buf) == p - buf && ftruncate(fd, p - buf) == 0, "truncated fixture");
	close(fd);
	check(ibnd_load_fabric(path, 0) == NULL, "truncated node table rejected");
	unlink(path);
}

static void kat_nodemap(void)
{
	char path[] = "/tmp/kat-nnmap-XXXXXX";
	const char *text = "# comment\n0x0002c90300000a01 \"core switch\" # trailing\n\n"
			   "0x0002c90300000b01 hca-one\n";
	nn_map_t *m;
	char *s, desc[65];
	int fd = mkstemp(path);

	check(fd >= 0 && write(fd, text, strlen(text)) == (ssize_t)strlen(text), "node-name map written");
	close(fd);
	m = open_node_name_map(path);
	check(m != NULL, "node-name map opens");
	s = remap_node_name(m, 0x0002c90300000a01ULL, "ignored");
	check(s && !strcmp(s, "core switch"), "quoted name remapped by GUID");
	free(s);
	s = remap_node_name(m, 0x0002c90300000b01ULL, "ignored");
	check(s && !strcmp(s, "hca-one"), "bare name remapped by GUID");
	free(s);
	memset(desc, 0, sizeof(desc));
	memcpy(desc, "unmapped\x01host", 13);
	s = remap_node_name(m, 0x1234, desc);
	check(s && !strcmp(s, "unmapped host"), "unknown GUID falls back to cleaned description");
	free(s);
	close_node_name_map(m);
	fd = open(path, 1);
	check(fd >= 0 && ftruncate(fd, 0) == 0 && write(fd, "zzz bad\n", 8) == 8, "bad map written");
	close(fd);
	check(open_node_name_map(path) == NULL, "malformed GUID rejected");
	unlink(path);
}

static void kat_mad(void)
{
	uint8_t mad[256] = {0};
	char out[256];
	uint64_t guid = 0;
	uint32_t v = 0;
	const uint8_t g[8] = {0x00, 0x02, 0xc9, 0x03, 0x00, 0x12, 0x34, 0x56};

	memcpy(mad + 12, g, 8);
	mad[2] = 2;
	mad[3] = 36;
	mad_decode_field(mad, IB_NODE_GUID_F, &guid);
	check(guid == 0x0002c90300123456ULL, "NodeInfo GUID decodes big-endian");
	mad_decode_field(mad, IB_NODE_NPORTS_F, &v);
	check(v == 36, "NodeInfo NumPorts decodes");
	mad_dump_val(IB_NODE_TYPE_F, out, sizeof(out), &(int){2});
	check(!strcmp(out, "Switch"), "node type 2 dumps as Switch");
	guid = 0;
	memset(mad, 0, sizeof(mad));
	guid = 0x1122334455667788ULL;
	mad_encode_field(mad, IB_NODE_GUID_F, &guid);
	check(mad[12] == 0x11 && mad[19] == 0x88, "NodeInfo GUID encodes big-endian");
	mad_dump_val(IB_NODE_GUID_F, out, sizeof(out), &guid);
	check(strstr(out, "0x1122334455667788") != NULL, "GUID dumps as hex");
}

int main(void)
{
	kat_cache();
	kat_nodemap();
	kat_mad();
	printf("KAT_DONE failed=%d\n", bad);
	return bad != 0;
}
