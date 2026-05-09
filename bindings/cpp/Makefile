# Makefile — build for the ITB C++ binding.
#
# The C++ binding is header-only: include/itb.h (a synced copy of the C
# binding's public header) plus include/itb/*.hpp (RAII wrappers around
# the C binding's `itb_*` API). There is no static archive to build —
# consumer applications include the headers and link against the C
# binding's archive plus libitb.so.
#
# Targets:
#   all (default): no-op (header-only library; run `cd ../c && make`
#                  to build the underlying static archive).
#   tests:         compiles every tests/test_*.cpp into tests/build/test_*.
#   test:          builds + runs every test (sequential).
#   bench:         compiles bench/bench_*.cpp into bench/build/bench_*.
#   eitb:          compiles eitb/eitb.cpp into eitb/build/eitb.
#   check-header:  re-runs check_header.sh (CI gate for header drift).
#   clean:         removes every generated artefact.
#
# Variables (override on the command line):
#   CXX           C++ compiler                      (default: c++)
#   CXXSTD        C++ standard for legacy targets   (default: c++17)
#   CXXSTD_WRAP   C++ standard for wrapper targets  (default: c++20)
#   OPT           optimisation flags                (default: -O2)
#   ITB_DIST      path to libitb.so dir             (default: ../../dist/linux-amd64)
#   ITB_C_DIR     path to C binding dir             (default: ../c)
#
# The format-deniability wrapper headers (include/itb/wrapper.hpp and
# the test_wrapper / bench_wrapper / eitb compilation units) consume
# `std::span`, which entered the standard in C++20. Every other target
# stays on the legacy C++17 baseline so existing consumers are
# unaffected.

CXX        ?= c++
CXXSTD     ?= c++17
CXXSTD_WRAP?= c++20
OPT        ?= -O2
WARN        = -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion \
              -Wold-style-cast -Wnon-virtual-dtor -Woverloaded-virtual
ITB_DIST   ?= ../../dist/linux-amd64
ITB_C_DIR  ?= ../c

CXXFLAGS       = -std=$(CXXSTD) $(OPT) $(WARN) -fPIC \
                 -Iinclude -I$(ITB_C_DIR)/include
CXXFLAGS_WRAP  = -std=$(CXXSTD_WRAP) $(OPT) $(WARN) -fPIC \
                 -Iinclude -I$(ITB_C_DIR)/include
LDFLAGS    = -L$(ITB_C_DIR)/build -L$(ITB_DIST) -Wl,-rpath,$(ITB_DIST)
LIBS       = -litb_c -litb

# ---- Default target --------------------------------------------------
all:
	@echo "C++ binding is header-only — nothing to build for the library itself."
	@echo "  build the underlying static archive: (cd $(ITB_C_DIR) && make)"
	@echo "  build the test binaries:             make tests"
	@echo "  build the bench binaries:            make bench"

# ---- Tests (Phase 7.5 wires individual test_*.cpp targets here) -----
TEST_SRCS         := $(wildcard tests/test_*.cpp)
TEST_BINS         := $(patsubst tests/test_%.cpp,tests/build/test_%,$(TEST_SRCS))
# Wrapper-targeted test binary requires the C++20 std::span surface.
TEST_WRAPPER_BINS := $(filter tests/build/test_wrapper,$(TEST_BINS))
TEST_LEGACY_BINS  := $(filter-out $(TEST_WRAPPER_BINS),$(TEST_BINS))

# Catch2 v3 — header-only, system package on Arch (`pacman -S catch2`).
CATCH2_LIBS := -lCatch2Main -lCatch2

tests: $(TEST_BINS)

# Legacy (C++17) test pattern.
$(TEST_LEGACY_BINS): tests/build/test_%: tests/test_%.cpp
	mkdir -p tests/build
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS) $(LIBS) $(CATCH2_LIBS)

# Wrapper test (C++20).
tests/build/test_wrapper: tests/test_wrapper.cpp include/itb/wrapper.hpp
	mkdir -p tests/build
	$(CXX) $(CXXFLAGS_WRAP) $< -o $@ $(LDFLAGS) $(LIBS) $(CATCH2_LIBS)

test: tests
	@./run_tests.sh

# ---- Bench (Phase 9) ------------------------------------------------
BENCH_SRCS         := $(wildcard bench/bench_*.cpp)
BENCH_BINS         := $(patsubst bench/%.cpp,bench/build/%,$(BENCH_SRCS))
# Wrapper-targeted bench binary requires the C++20 std::span surface.
BENCH_WRAPPER_BINS := $(filter bench/build/bench_wrapper,$(BENCH_BINS))
BENCH_LEGACY_BINS  := $(filter-out $(BENCH_WRAPPER_BINS),$(BENCH_BINS))

bench: $(BENCH_BINS)

# Legacy (C++17) bench pattern.
$(BENCH_LEGACY_BINS): bench/build/%: bench/%.cpp $(wildcard bench/*.hpp)
	mkdir -p bench/build
	$(CXX) $(CXXFLAGS) -Ibench $< -o $@ $(LDFLAGS) $(LIBS)

# Wrapper bench (C++20).
bench/build/bench_wrapper: bench/bench_wrapper.cpp include/itb/wrapper.hpp \
                           $(wildcard bench/*.hpp)
	mkdir -p bench/build
	$(CXX) $(CXXFLAGS_WRAP) -Ibench $< -o $@ $(LDFLAGS) $(LIBS)

# ---- eitb (wrapper × ITB matrix runner, C++20) ----------------------
EITB_SHA256_DIR := $(ITB_C_DIR)/eitb

eitb: eitb/build/eitb

# sha256 helper is shared with the C binding's eitb runner; compile as
# a C TU and link.
eitb/build/sha256.o: $(EITB_SHA256_DIR)/sha256.c $(EITB_SHA256_DIR)/sha256.h
	mkdir -p eitb/build
	$(CC) -std=c11 $(OPT) -Wall -Wextra -fPIC \
	    -I$(EITB_SHA256_DIR) -c $< -o $@

eitb/build/eitb: eitb/eitb.cpp include/itb/wrapper.hpp eitb/build/sha256.o
	mkdir -p eitb/build
	$(CXX) $(CXXFLAGS_WRAP) -I$(EITB_SHA256_DIR) \
	    eitb/eitb.cpp eitb/build/sha256.o \
	    -o $@ $(LDFLAGS) $(LIBS)

# ---- Header drift gate ----------------------------------------------
check-header:
	@./check_header.sh

# ---- Cleanup ---------------------------------------------------------
clean:
	rm -rf tests/build bench/build eitb/build

.PHONY: all tests test bench eitb check-header clean
