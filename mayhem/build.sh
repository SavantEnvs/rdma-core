#!/usr/bin/env bash
# Builds rdma-core's userspace libraries (libibmad, libibumad, libibnetdisc, util) twice with upstream's
# CMake build, then the libFuzzer harnesses, their -standalone reproducers and the KAT probe test.sh runs:
#   mayhem/_build/fuzz  sanitized (ASan+UBSan, halting) + -fsanitize=fuzzer-no-link, DWARF 3: fuzz targets
#   mayhem/_build/test  upstream's normal flags, no sanitizers: the KAT probe
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
B="$SRC/mayhem/_build"
TARGETS="ibmad-static ibumad-static ibnetdisc-static rdma_util"

# CMake drops its cache (including -DENABLE_STATIC) when it re-resolves the compiler name on a re-run,
# so every run configures from scratch.
rm -rf "$B/fuzz" "$B/test"

configure() { # <dir> <c flags> <extra cmake args>
  cmake -S "$SRC" -B "$1" -GNinja -DIN_PLACE=1 -DENABLE_STATIC=1 -DNO_PYVERBS=1 -DNO_MAN_PAGES=1 \
    -DENABLE_RESOLVE_NEIGH=0 \
    -DCMAKE_C_COMPILER="$CC" -DCMAKE_C_FLAGS="$2" "${@:3}"
}

# 1) Sanitized libraries. -fsanitize=fuzzer-no-link goes on unconditionally, so the libraries carry
#    SanCov edges whether or not SANITIZER_FLAGS is empty. Upstream links each library's shared object
#    with --no-undefined; the sanitizer runtime is not in a shared object, so allow undefs there (only the
#    static archives are used).
configure "$B/fuzz" "$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo "-DCMAKE_C_FLAGS_RELWITHDEBINFO=-O1 $DEBUG_FLAGS" \
  "-DCMAKE_SHARED_LINKER_FLAGS_RELWITHDEBINFO=-Wl,-z,undefs"
ninja -C "$B/fuzz" -j"$MAYHEM_JOBS" $TARGETS

FUZZ_INC="-I$B/fuzz/include -I$SRC/util -I$SRC"
FUZZ_LIBS="$B/fuzz/lib/statics/libibnetdisc.a $B/fuzz/lib/statics/libibmad.a $B/fuzz/lib/statics/libibumad.a $B/fuzz/util/librdma_util.a"

# 2) Harnesses: fuzzer binary + standalone reproducer, LSan off via lsan_off.o.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$B/lsan_off.o"
for t in fuzz_ibnd_cache fuzz_node_name_map fuzz_ibmad; do
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE $FUZZ_INC "$SRC/mayhem/$t.c" "$B/lsan_off.o" \
      $FUZZ_LIBS -o "$SRC/$t"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $FUZZ_INC "$STANDALONE_FUZZ_MAIN" "$SRC/mayhem/$t.c" "$B/lsan_off.o" \
      $FUZZ_LIBS -o "$SRC/$t-standalone"
done

# 3) Test build: upstream's own flags, no sanitizers; test.sh only runs the probe.
configure "$B/test" "$COVERAGE_FLAGS" -DCMAKE_BUILD_TYPE=RelWithDebInfo
ninja -C "$B/test" -j"$MAYHEM_JOBS" $TARGETS
$CC -O1 $COVERAGE_FLAGS -I"$B/test/include" -I"$SRC/util" -I"$SRC" "$SRC/mayhem/kat_probe.c" \
    "$B/test/lib/statics/libibnetdisc.a" "$B/test/lib/statics/libibmad.a" "$B/test/lib/statics/libibumad.a" \
    "$B/test/util/librdma_util.a" $COVERAGE_FLAGS -o "$SRC/kat_probe"
