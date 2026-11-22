package near

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"math/big"
	"testing"
)

// The bytes @near-js/transactions 2.5.1 encodes for the same transaction.
const vector = "0d0000006167656e742e746573746e6574006e7a1cdd29b0b78fd13af4c5598feff4ef2a97166e3ca6f2e4fbfccd80505bf10700000000000000150000007661756c742e6578616d706c652e746573746e6574030303030303030303030303030303030303030303030303030303030303030301000000020700000070726570617265070000007b2261223a317d00407a10f35a000001000000000000000000000000000000"

func TestTransactionIsTheProtocolsBytes(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32))
	var block [32]byte
	copy(block[:], bytes.Repeat([]byte{3}, 32))
	got, err := Transaction("agent.testnet", key.Public().(ed25519.PublicKey), 7, "vault.example.testnet", block,
		[]FunctionCall{{Method: "prepare", Args: []byte(`{"a":1}`), Gas: 100_000_000_000_000, Deposit: big.NewInt(1)}})
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != vector {
		t.Fatalf("got %x", got)
	}
	signed, hash := Sign(got, key)
	if len(signed) != len(got)+65 || signed[len(got)] != 0 || !ed25519.Verify(key.Public().(ed25519.PublicKey), hash[:], signed[len(got)+1:]) {
		t.Fatal("signature")
	}
}

func TestBase58(t *testing.T) {
	for _, data := range [][]byte{{}, {0}, {0, 0, 1}, bytes.Repeat([]byte{255}, 32)} {
		back, err := DecodeBase58(Base58(data))
		if err != nil || !bytes.Equal(back, data) {
			t.Fatalf("%x -> %q -> %x", data, Base58(data), back)
		}
	}
	if Base58([]byte("hello world")) != "StV1DL6CwTryKyV" {
		t.Fatal(Base58([]byte("hello world")))
	}
	if _, err := DecodeBase58("0OIl"); err == nil {
		t.Fatal("decoded outside the alphabet")
	}
}

func TestTransactionRefusesWhatItCannotWrite(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	public := key.Public().(ed25519.PublicKey)
	if _, err := Transaction("Bad Account", public, 1, "vault.testnet", [32]byte{}, nil); err == nil {
		t.Fatal("bad signer")
	}
	huge := new(big.Int).Lsh(big.NewInt(1), 128)
	if _, err := Transaction("a.testnet", public, 1, "vault.testnet", [32]byte{}, []FunctionCall{{Method: "x", Deposit: huge}}); err == nil {
		t.Fatal("deposit above u128")
	}
}
