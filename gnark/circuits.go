package main

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

// Keep this order in sync with the public input indexes in parentCircuit.
type publicState struct {
	Start  frontend.Variable `gnark:",public"`
	End    frontend.Variable `gnark:",public"`
	Height frontend.Variable `gnark:",public"`
	Count  frontend.Variable `gnark:",public"`
}

type leafCircuit struct {
	State publicState
}

func (c *leafCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.State.End, api.Add(c.State.Start, 1))
	api.AssertIsEqual(c.State.Height, 0)
	api.AssertIsEqual(c.State.Count, 1)
	return nil
}

type childProof struct {
	Proof   stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	Witness stdgroth16.Witness[sw_bn254.ScalarField]
}

type parentCircuit struct {
	State       publicState
	Left, Right childProof
	ChildKey    stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl] `gnark:"-"`
}

func (c *parentCircuit) Define(api frontend.API) error {
	verifier, err := stdgroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return err
	}
	for _, child := range []childProof{c.Left, c.Right} {
		if err := verifier.AssertProof(c.ChildKey, child.Proof, child.Witness, stdgroth16.WithSubgroupCheck()); err != nil {
			return err
		}
	}

	scalars, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	// The verifier uses emulated scalars. Both circuits have the same BN254
	// scalar field, so use the child inputs as native scalars for the join.
	native := func(value *emulated.Element[sw_bn254.ScalarField]) frontend.Variable {
		return api.FromBinary(scalars.ToBitsCanonical(value)...)
	}
	left, right := c.Left.Witness.Public, c.Right.Witness.Public
	const (
		start = iota
		end
		height
		count
	)
	leftHeight := native(&left[height])
	api.AssertIsEqual(native(&left[end]), native(&right[start]))
	api.AssertIsEqual(leftHeight, native(&right[height]))
	api.AssertIsEqual(c.State.Start, native(&left[start]))
	api.AssertIsEqual(c.State.End, native(&right[end]))
	api.AssertIsEqual(c.State.Height, api.Add(leftHeight, 1))
	api.AssertIsEqual(c.State.Count, api.Add(native(&left[count]), native(&right[count])))
	return nil
}
