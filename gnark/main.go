package main

import (
	"fmt"
	"log"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

var field = ecc.BN254.ScalarField()

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

func (level proofLevel) prove(assignment frontend.Circuit, expected publicState) (provedStatement, error) {
	full, err := frontend.NewWitness(assignment, field)
	if err != nil {
		return provedStatement{}, fmt.Errorf("build prover witness: %w", err)
	}
	proof, err := groth16.Prove(level.constraints, level.provingKey, full, stdgroth16.GetNativeProverOptions(field, field))
	if err != nil {
		return provedStatement{}, fmt.Errorf("prove: %w", err)
	}
	// Both circuits expose the same public inputs in the same order.
	public, err := frontend.NewWitness(&leafCircuit{State: expected}, field, frontend.PublicOnly())
	if err != nil {
		return provedStatement{}, fmt.Errorf("build verifier witness: %w", err)
	}
	if err := groth16.Verify(proof, level.verifyingKey, public, stdgroth16.GetNativeVerifierOptions(field, field)); err != nil {
		return provedStatement{}, fmt.Errorf("verify: %w", err)
	}
	return provedStatement{proof, public}, nil
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

func run() error {
	level, err := setupLevel(0, &leafCircuit{})
	if err != nil {
		return err
	}
	children := make([]provedStatement, 4)
	for i := range children {
		state := publicState{Start: i + 1, End: i + 2, Height: 0, Count: 1}
		children[i], err = level.prove(&leafCircuit{State: state}, state)
		if err != nil {
			return fmt.Errorf("leaf %d: %w", i+1, err)
		}
	}
	fmt.Println("Verified 4 leaf proofs")

	for height := 1; height <= 2; height++ {
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
			start := i*count + 1
			state := publicState{Start: start, End: start + count, Height: height, Count: count}
			fmt.Printf("Proving level %d proof %d of %d\n", height, i+1, len(parents))
			parents[i], err = level.prove(&parentCircuit{State: state, Left: left, Right: right}, state)
			if err != nil {
				return fmt.Errorf("level %d proof %d: %w", height, i+1, err)
			}
			fmt.Printf("Verified start=%v end=%v height=%v count=%v\n", state.Start, state.End, state.Height, state.Count)
		}
		children = parents
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
