/* Fuzzes libibmad's MAD field decoders and dumpers: every named field is decoded out of
 * the input (a MAD payload) and pretty-printed, then the composite per-attribute dumpers
 * run over the same payload. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <infiniband/mad.h>

#define MAD_PAYLOAD 2048 /* >= the largest field end offset in ib_mad_f[] */

static char out[8192];

struct composite {
	ib_mad_dump_fn *fn;
	int valsz;
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const struct composite comps[] = {
		{ mad_dump_nodeinfo, 64 },    { mad_dump_portinfo, 64 },
		{ mad_dump_switchinfo, 64 },  { mad_dump_nodedesc, 64 },
		{ mad_dump_perfcounters, 64 },{ mad_dump_perfcounters_ext, 64 },
		{ mad_dump_classportinfo, 64 },{ mad_dump_portsamples_control, 64 },
		{ mad_dump_portsamples_result, 64 },{ mad_dump_portinfo_ext, 64 },
		{ mad_dump_cc_congestioninfo, 64 },{ mad_dump_cc_switchcongestionsetting, 64 },
		{ mad_dump_cc_cacongestionsetting, 64 },{ mad_dump_cc_timestamp, 64 },
		{ mad_dump_perfcounters_xmt_sl, 64 },{ mad_dump_perfcounters_rcv_sl, 64 },
		{ mad_dump_port_ext_speeds_counters, 64 },
		{ mad_dump_perfcounters_port_op_rcv_counters, 64 },
		{ mad_dump_mlnx_ext_port_info, 64 },
	};
	uint8_t payload[MAD_PAYLOAD];
	uint64_t val[128];
	unsigned i;
	int f;

	/* a MAD is a fixed-size packet; a payload shorter than the buffer is zero-extended */
	memset(payload, 0, sizeof(payload));
	memcpy(payload, data, size < sizeof(payload) ? size : sizeof(payload));

	for (f = IB_NO_FIELD + 1; f < IB_FIELD_LAST_; f++) {
		/* the *_FIRST_F/*_LAST_F range markers are empty ib_mad_f[] entries (no name, no dump fn) */
		if (!mad_field_name(f)[0])
			continue;
		memset(val, 0, sizeof(val));
		mad_decode_field(payload, f, val);
		mad_dump_field(f, out, sizeof(out), val);
		mad_dump_val(f, out, sizeof(out), val);
	}
	for (i = 0; i < sizeof(comps) / sizeof(comps[0]); i++)
		comps[i].fn(out, sizeof(out), payload, comps[i].valsz);
	return 0;
}
