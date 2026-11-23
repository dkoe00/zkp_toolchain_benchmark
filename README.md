# ZKP Toolchain Benchmark

## gnark

Run from the repository root on macOS or Linux with Make, Go, and Python 3.9
or later on your `PATH`.

```sh
make bench-gnark
make bench-gnark N=4 RUNS=1
```

The first command runs five repetitions per size, in the order
`1, 2, 4, 8, 16, 32, 64, 128`. The second runs one repetition with four
leaves. `N` accepts a power of two from 1 through 128 or a quoted list such as
`N="2 4 8"`. `RUNS` sets the number of repetitions per size. The runner finishes
all repetitions for one size before moving to the next size in the list.

The runner builds the executable once with Go 1.27.3. Each repetition starts a
fresh process with `GOMAXPROCS=4`, recompiles the circuits, and runs fresh
Groth16 setup at every level.

### Results

Each run writes to a new `bench-results/gnark.<suffix>/` directory.

- `config.txt` records the size order, repetitions, CPU model, architecture,
  logical CPU count, RAM, OS, and parallelism. It includes `go version -m`
  output with Go and dependency versions and embedded build settings.
- `samples.csv` has one row per applicable metric for each repetition, with
  its exit code and last emitted stage. It includes measurements produced
  before a sample failed. A blank exit code means launch failed.
- `summary.csv` groups successful samples by size, phase, level, and metric.
  It reports count, mean, median, and interquartile range (IQR). Quartiles use
  inclusive linear interpolation, with IQR zero for a single sample.
- `failure.log` is created on a sample failure and holds the process output or
  launch error.

The first sample failure stops the run and reports its size, repetition, and
last stage. Completed samples stay in both CSVs. To find the largest `N` whose
final proof verified, take the maximum `n` among `verify_final` rows in
`samples.csv`. Use exit code `0` to identify samples that also completed all
leaf verifications.

### Measurement boundaries

Phase durations and process wall time are recorded in nanoseconds. Leaves are
level 0, aggregation levels are reported separately, and process metrics have
a blank level.

| Phase | What is measured |
| --- | --- |
| `process` | Wall time from executable launch to exit and the OS-reported peak RSS in bytes. The executable build happens before sampling. |
| `compile`, `setup` | Circuit compilation and Groth16 key generation, timed separately at each level. |
| `prove_leaves`, `prove_aggregation` | Proof count and the sum of prover-call times at each level. Witness preparation and child proof conversion happen outside these timers. |
| `final_proof_size` | Byte length of gnark's serialized final proof. |
| `verify_final`, `verify_leaves` | Proof count and verification time for the final proof and all leaves, measured separately. Both timers include proof decoding and expected public witness preparation. Keys are already in memory, and proof serialization happens beforehand. |

At `N=1`, the single leaf is also the final proof and is used in both
verification measurements.

### Workload

Groth16 leaf and parent circuits run on BN254. The reference chain starts at
`1`. Each leaf proves eight successive applications of `H` on the BN254 scalar
field, so `N` leaves cover `8N` applications. Each parent verifies two child
proofs and joins their endpoints.

`H(x)` uses gnark-crypto v0.21.0's Poseidon2 Merkle–Damgård hash with a zero
initial state and one 32-byte big-endian field element per call. The width-2
permutation uses 6 full rounds, 50 partial rounds, and an `x⁵` S-box. The hash
adds `x` to the second output of the permutation on `(0, x)`.

For input `1`, the decimal reference output is
`12157562999385135173166708316607836110878334226144932937475223226141207470306`.

Poseidon2 remains provisional until gnark, Halo2, and Noir/Barretenberg match
a common hash and reference vector.
