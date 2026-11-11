# add_to_portlid_hash: shift exponent from an unvalidated cached LMC

`lmc255.cache` is a fabric cache whose first port record has `lmc = 255`.

- Reproduce: `/mayhem/fuzz_ibnd_cache-standalone mayhem/fuzz_ibnd_cache/known-findings/lmc-shift-exponent/lmc255.cache`
- Report: `libibnetdisc/ibnetdisc.c:695:26: runtime error: shift exponent 255 is too large for 32-bit type 'int'`
- Cause: `_load_port()` in `ibnetdisc_cache.c` copies the LMC byte from the file as is, and
  `add_to_portlid_hash()` computes `((1 << port->lmc) - 1)`. An LMC is a 3-bit field (0..7) on the wire, but any
  value 0..255 is accepted from a cache file, so the shift is undefined for lmc >= 31.
- Impact: undefined behaviour while loading an untrusted cache file (`ibnetdiscover --load-cache`, `ibcacheedit`);
  the resulting mask feeds the LID hash insertion that follows.
- Fix: reject (or mask) the value in `_load_port()` (`if (port->lmc > 7) goto cleanup;`).
