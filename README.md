# ZKP Toolchain Benchmark

(Work in progress)

Benchmarking of several ZKP toolchains commonly used in 2026

## gnark

The Poseidon2 recursion prototype runs from the `gnark/` directory.

```sh
cd gnark
GOTOOLCHAIN=go1.27.3 GOMAXPROCS=4 go run .
```

Each leaf proves eight applications of `H` on the BN254 scalar field. `H(x)`
uses gnark-crypto v0.21.0's Poseidon2 Merkle–Damgård hash with a zero initial
state and one 32-byte big-endian field element per call. The width-2 permutation
uses 6 full rounds, 50 partial rounds, and an `x⁵` S-box. The hash adds `x` to
the second output of the permutation on `(0, x)`.

For input `1`, the decimal reference output is
`12157562999385135173166708316607836110878334226144932937475223226141207470306`.
