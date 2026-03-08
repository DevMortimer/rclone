package api

import (
	"math/big"
	"testing"
)

func TestAppleSRPUsesPaddedClientEphemeralForU(t *testing.T) {
	shortA := big.NewInt(0x1234)
	B := big.NewInt(0x5678)

	got := hashToInt(padSRP(shortA), padSRP(B))
	if got.Sign() == 0 {
		t.Fatal("hashToInt(pad(A), pad(B)) returned zero")
	}

	unpadded := hashToInt(bytesFromBigInt(shortA), padSRP(B))
	if got.Cmp(unpadded) == 0 {
		t.Fatal("padded and unpadded SRP scrambling parameters unexpectedly match")
	}
}
