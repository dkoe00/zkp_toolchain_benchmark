package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

var field = ecc.BN254.ScalarField()

// referenceChain computes H repeatedly, starting at 1. Each call to H hashes
// one canonical field element from the zero initial state.
func referenceChain(leafCount int) ([]fr.Element, error) {
	chain := make([]fr.Element, leafCount*hashesPerLeaf+1)
	chain[0].SetOne()
	hasher := poseidon2.NewMerkleDamgardHasher()
	for i := 1; i < len(chain); i++ {
		hasher.Reset()
		if _, err := hasher.Write(chain[i-1].Marshal()); err != nil {
			return nil, fmt.Errorf("hash reference chain step %d: %w", i, err)
		}
		chain[i].SetBytes(hasher.Sum(nil))
	}
	return chain, nil
}

func leafState(chain []fr.Element, index int) publicState {
	start := index * hashesPerLeaf
	return publicState{Start: chain[start], End: chain[start+hashesPerLeaf], Height: 0, Count: 1}
}

type proofLevel struct {
	constraints  constraint.ConstraintSystem
	provingKey   groth16.ProvingKey
	verifyingKey groth16.VerifyingKey
}

type provedStatement struct {
	proof  groth16.Proof
	public witness.Witness
}

func stage(phase string, height int) {
	fmt.Printf("stage,%s,%d\n", phase, height)
}

func reportTiming(phase string, height int, elapsed time.Duration, proofCount int) {
	fmt.Printf("measurement,%s,%d,%d,%d,0\n", phase, height, elapsed.Nanoseconds(), proofCount)
}

func setupLevel(height int, circuit frontend.Circuit) (proofLevel, error) {
	stage("compile", height)
	start := time.Now()
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, circuit)
	elapsed := time.Since(start)
	if err != nil {
		return proofLevel{}, fmt.Errorf("compile level %d: %w", height, err)
	}
	reportTiming("compile", height, elapsed, 0)
	stage("setup", height)
	start = time.Now()
	pk, vk, err := groth16.Setup(ccs)
	elapsed = time.Since(start)
	if err != nil {
		return proofLevel{}, fmt.Errorf("set up level %d: %w", height, err)
	}
	reportTiming("setup", height, elapsed, 0)
	return proofLevel{ccs, pk, vk}, nil
}

func (level proofLevel) parent() (*parentCircuit, error) {
	key, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](level.verifyingKey)
	if err != nil {
		return nil, err
	}
	placeholder := func() childProof {
		return childProof{
			Proof:   stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](level.constraints),
			Witness: stdgroth16.PlaceholderWitness[sw_bn254.ScalarField](level.constraints),
		}
	}
	return &parentCircuit{Left: placeholder(), Right: placeholder(), ChildKey: key}, nil
}

func (level proofLevel) prove(assignment frontend.Circuit) (provedStatement, time.Duration, error) {
	full, err := frontend.NewWitness(assignment, field)
	if err != nil {
		return provedStatement{}, 0, fmt.Errorf("build prover witness: %w", err)
	}
	public, err := full.Public()
	if err != nil {
		return provedStatement{}, 0, fmt.Errorf("extract public witness: %w", err)
	}
	options := stdgroth16.GetNativeProverOptions(field, field)
	start := time.Now()
	proof, err := groth16.Prove(level.constraints, level.provingKey, full, options)
	elapsed := time.Since(start)
	if err != nil {
		return provedStatement{}, 0, fmt.Errorf("prove: %w", err)
	}
	return provedStatement{proof, public}, elapsed, nil
}

func encodeProof(proof groth16.Proof) ([]byte, error) {
	var buffer bytes.Buffer
	if _, err := proof.WriteTo(&buffer); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func verifyEncodedProof(encoded []byte, key groth16.VerifyingKey, expected publicState) error {
	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(encoded)); err != nil {
		return fmt.Errorf("decode proof: %w", err)
	}
	// Both circuits expose the same public inputs in the same order.
	public, err := frontend.NewWitness(&leafCircuit{State: expected}, field, frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("build verifier witness: %w", err)
	}
	return groth16.Verify(proof, key, public, stdgroth16.GetNativeVerifierOptions(field, field))
}

func (p provedStatement) child() (childProof, error) {
	proof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](p.proof)
	if err != nil {
		return childProof{}, err
	}
	public, err := stdgroth16.ValueOfWitness[sw_bn254.ScalarField](p.public)
	if err != nil {
		return childProof{}, err
	}
	return childProof{Proof: proof, Witness: public}, nil
}

func run(leafCount int) error {
	if leafCount < 1 || leafCount > 128 || leafCount&(leafCount-1) != 0 {
		return errors.New("-n must be a power of two between 1 and 128")
	}
	stage("reference_chain", 0)
	chain, err := referenceChain(leafCount)
	if err != nil {
		return err
	}

	level, err := setupLevel(0, &leafCircuit{})
	if err != nil {
		return err
	}
	leafKey := level.verifyingKey
	children := make([]provedStatement, leafCount)
	stage("prove_leaves", 0)
	var leafProvingTime time.Duration
	for i := range children {
		leaf, elapsed, err := level.prove(&leafCircuit{State: leafState(chain, i)})
		if err != nil {
			return fmt.Errorf("leaf %d: %w", i+1, err)
		}
		children[i] = leaf
		leafProvingTime += elapsed
	}
	reportTiming("prove_leaves", 0, leafProvingTime, leafCount)

	stage("serialize_leaf_proofs", 0)
	encodedLeaves := make([][]byte, leafCount)
	for i, leaf := range children {
		encodedLeaves[i], err = encodeProof(leaf.proof)
		if err != nil {
			return fmt.Errorf("serialize leaf proof %d: %w", i+1, err)
		}
	}

	height := 0
	for len(children) > 1 {
		height++
		stage("prepare_parent", height)
		circuit, err := level.parent()
		if err != nil {
			return fmt.Errorf("build level %d circuit: %w", height, err)
		}
		level, err = setupLevel(height, circuit)
		if err != nil {
			return err
		}
		parents := make([]provedStatement, len(children)/2)
		count := 1 << height
		stage("prove_aggregation", height)
		var aggregationProvingTime time.Duration
		for i := range parents {
			left, err := children[2*i].child()
			if err != nil {
				return fmt.Errorf("convert left child at level %d: %w", height, err)
			}
			right, err := children[2*i+1].child()
			if err != nil {
				return fmt.Errorf("convert right child at level %d: %w", height, err)
			}
			start := i * count * hashesPerLeaf
			end := start + count*hashesPerLeaf
			state := publicState{Start: chain[start], End: chain[end], Height: height, Count: count}
			parent, elapsed, err := level.prove(&parentCircuit{State: state, Left: left, Right: right})
			if err != nil {
				return fmt.Errorf("level %d proof %d: %w", height, i+1, err)
			}
			parents[i] = parent
			aggregationProvingTime += elapsed
		}
		reportTiming("prove_aggregation", height, aggregationProvingTime, len(parents))
		children = parents
	}

	encodedFinal := encodedLeaves[0]
	if height > 0 {
		stage("serialize_final_proof", height)
		encodedFinal, err = encodeProof(children[0].proof)
		if err != nil {
			return fmt.Errorf("serialize final proof: %w", err)
		}
	}
	fmt.Printf("measurement,final_proof_size,%d,0,1,%d\n", height, len(encodedFinal))

	stage("verify_final", height)
	start := time.Now()
	end := len(chain) - 1
	expected := publicState{Start: chain[0], End: chain[end], Height: height, Count: leafCount}
	err = verifyEncodedProof(encodedFinal, level.verifyingKey, expected)
	elapsed := time.Since(start)
	if err != nil {
		return fmt.Errorf("verify final proof: %w", err)
	}
	reportTiming("verify_final", height, elapsed, 1)

	stage("verify_leaves", 0)
	start = time.Now()
	for i, encoded := range encodedLeaves {
		if err := verifyEncodedProof(encoded, leafKey, leafState(chain, i)); err != nil {
			return fmt.Errorf("verify leaf proof %d: %w", i+1, err)
		}
	}
	reportTiming("verify_leaves", 0, time.Since(start), leafCount)
	return nil
}

func main() {
	leafCount := flag.Int("n", 4, "number of leaves (1, 2, 4, 8, 16, 32, 64, or 128)")
	flag.Parse()
	if err := run(*leafCount); err != nil {
		log.Fatal(err)
	}
}
