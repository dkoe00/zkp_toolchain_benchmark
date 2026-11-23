# ZKP Toolchain Benchmark

## gnark

Run from the repository root on macOS or Linux with Python 3.9 or later.

```sh
make bench-gnark
make bench-gnark N=4 RUNS=1
```

The command builds once with Go 1.27.3. The runner starts one fresh process at a
time with `GOMAXPROCS=4` and fresh Groth16 setup at every level. Defaults are
five repetitions per size for `1, 2, 4, 8, 16, 32, 64, 128`. Override them with
`RUNS` and `N`. For multiple sizes, use a quoted list such as `N="2 4 8"`.

### Results

Results go under `bench-results/gnark.<suffix>/`.

- `config.txt` records sizes, repetitions, hardware, OS, Go and dependency
  versions, and parallelism.
- `samples.csv` has one row per applicable metric for each repetition, with
  its exit code and last stage. It includes partial measurements from a
  failed process. A blank exit code means launch failed.
- `summary.csv` groups successful samples by size, phase, level, and metric.
  It reports count, mean, median, and IQR. Quartiles use inclusive linear
  interpolation, with IQR zero for a single sample.
- `failure.log` holds the failed process's output or launch error.

The first failure stops the run and reports its size, repetition, and last
stage. Completed samples stay in both CSVs.

### Measurement boundaries

- Process wall time is measured in nanoseconds from launch to exit. Peak RSS
  is the OS-reported maximum for the child process, in bytes. The build happens
  before sampling.
- Compilation and setup are timed separately at each level. Proving time sums
  prover calls per level. Witness preparation and child proof conversion are
  outside the proving timers. Leaves are level 0.
- Final proof size is the byte length of gnark's serialized proof.
- Final and leaf verification include decoding and expected public witness
  preparation. Keys are already in memory and serialization happens beforehand.

### Workload

Groth16 leaf and parent circuits run on BN254. Each parent verifies two child
proofs and joins their endpoints. Each leaf proves eight applications of `H`
on the BN254 scalar field. `H(x)` uses gnark-crypto v0.21.0's Poseidon2
Merkle–Damgård hash with a zero initial
state and one 32-byte big-endian field element per call. The width-2 permutation
uses 6 full rounds, 50 partial rounds, and an `x⁵` S-box. The hash adds `x` to
the second output of the permutation on `(0, x)`.

For input `1`, the decimal reference output is
`12157562999385135173166708316607836110878334226144932937475223226141207470306`.

Poseidon2 remains provisional until gnark, Halo2, and Noir/Barretenberg match
a common hash and reference vector.
