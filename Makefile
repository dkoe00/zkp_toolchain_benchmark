N ?= 1 2 4 8 16 32 64 128
RUNS ?= 5

.PHONY: bench-gnark
bench-gnark:
	GOTOOLCHAIN=go1.27.3 GOMAXPROCS=4 python3 bench.py gnark "$(RUNS)" $(N)
