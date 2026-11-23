package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"math/bits"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	csbn254 "github.com/consensys/gnark/constraint/bn254"
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

type proofLevel struct {
	constraints  constraint.ConstraintSystem
	provingKey   groth16.ProvingKey
	verifyingKey groth16.VerifyingKey
}

type provedStatement struct {
	proof  groth16.Proof
	public witness.Witness
}

func setupLevel(height int, circuit frontend.Circuit) (proofLevel, error) {
	fmt.Printf("Compiling level %d\n", height)
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, circuit)
	if err != nil {
		return proofLevel{}, fmt.Errorf("compile level %d: %w", height, err)
	}
	fmt.Printf("Generating keys for level %d\n", height)
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return proofLevel{}, fmt.Errorf("set up level %d: %w", height, err)
	}
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

func (level proofLevel) prove(assignment frontend.Circuit) (provedStatement, error) {
	full, err := frontend.NewWitness(assignment, field)
	if err != nil {
		return provedStatement{}, fmt.Errorf("build prover witness: %w", err)
	}
	public, err := full.Public()
	if err != nil {
		return provedStatement{}, fmt.Errorf("extract public witness: %w", err)
	}
	proof, err := groth16.Prove(level.constraints, level.provingKey, full, stdgroth16.GetNativeProverOptions(field, field))
	if err != nil {
		return provedStatement{}, fmt.Errorf("prove: %w", err)
	}
	return provedStatement{proof, public}, nil
}

func (level proofLevel) verify(proof groth16.Proof, public witness.Witness) error {
	return groth16.Verify(proof, level.verifyingKey, public, stdgroth16.GetNativeVerifierOptions(field, field))
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

func run(leafCount int, checkMismatch bool) error {
	if leafCount < 1 || leafCount > 128 || leafCount&(leafCount-1) != 0 {
		return errors.New("-n must be a power of two between 1 and 128")
	}
	if checkMismatch && leafCount < 2 {
		return errors.New("-check-mismatch requires -n of at least 2")
	}
	chain, err := referenceChain(leafCount)
	if err != nil {
		return err
	}
	fmt.Printf("Poseidon2 H(1)=%s\n", chain[1].String())

	level, err := setupLevel(0, &leafCircuit{})
	if err != nil {
		return err
	}
	children := make([]provedStatement, leafCount)
	for i := range children {
		start := i * hashesPerLeaf
		state := publicState{Start: chain[start], End: chain[start+hashesPerLeaf], Height: 0, Count: 1}
		children[i], err = level.prove(&leafCircuit{State: state})
		if err != nil {
			return fmt.Errorf("leaf %d: %w", i+1, err)
		}
		if checkMismatch && i < 2 {
			if err := level.verify(children[i].proof, children[i].public); err != nil {
				return fmt.Errorf("verify leaf %d for mismatch check: %w", i+1, err)
			}
		}
	}

	for height := 1; len(children) > 1; height++ {
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
			fmt.Printf("Proving level %d proof %d of %d\n", height, i+1, len(parents))
			parents[i], err = level.prove(&parentCircuit{State: state, Left: left, Right: right})
			if err != nil {
				return fmt.Errorf("level %d proof %d: %w", height, i+1, err)
			}
			if checkMismatch && height == 1 && i == 0 {
				// Reverse the two verified leaves. Both outer endpoints are x_8,
				// but the join would require x_16 to equal x_0.
				reversed := publicState{Start: chain[hashesPerLeaf], End: chain[hashesPerLeaf], Height: 1, Count: 2}
				_, err := level.prove(&parentCircuit{State: reversed, Left: right, Right: left})
				if err == nil {
					return errors.New("proved a parent with mismatched child endpoints")
				}
				var unsatisfied *csbn254.UnsatisfiedConstraintError
				if !errors.As(err, &unsatisfied) {
					return fmt.Errorf("prove mismatched children: %w", err)
				}
				fmt.Printf("Rejected two valid leaves with a mismatched join at constraint %d\n", unsatisfied.CID)
			}
		}
		children = parents
	}

	end := len(chain) - 1
	height := bits.Len(uint(leafCount)) - 1
	expected := publicState{Start: chain[0], End: chain[end], Height: height, Count: leafCount}
	// Both circuits expose the same public inputs in the same order.
	public, err := frontend.NewWitness(&leafCircuit{State: expected}, field, frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("build final verifier witness: %w", err)
	}
	if err := level.verify(children[0].proof, public); err != nil {
		return fmt.Errorf("verify final proof: %w", err)
	}
	fmt.Printf("Verified N=%d start=%s end=%s height=%d count=%d (%d hashes)\n", leafCount, chain[0].String(), chain[end].String(), height, leafCount, end)
	return nil
}

func main() {
	leafCount := flag.Int("n", 4, "number of leaves (1, 2, 4, 8, 16, 32, 64, or 128)")
	checkMismatch := flag.Bool("check-mismatch", false, "check that a parent rejects two valid leaves in reverse order (requires -n >= 2)")
	flag.Parse()
	if err := run(*leafCount, *checkMismatch); err != nil {
		log.Fatal(err)
	}
}
