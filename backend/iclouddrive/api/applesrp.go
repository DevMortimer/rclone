package api

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"golang.org/x/crypto/pbkdf2"
)

var (
	appleSRPModulus = mustParseHexInt("" +
		"AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050" +
		"A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50" +
		"E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8" +
		"55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B" +
		"CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748" +
		"544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6" +
		"AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6" +
		"94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73")
	appleSRPGenerator = big.NewInt(2)
	appleSRPByteLen   = 256
)

type appleSRPSession struct {
	secret *big.Int
	public *big.Int
}

type appleSRPProofs struct {
	ClientProof []byte
	ServerProof []byte
	SessionKey  []byte
}

func mustParseHexInt(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("invalid SRP modulus")
	}
	return n
}

func newAppleSRPSession() (*appleSRPSession, error) {
	max := new(big.Int).Sub(appleSRPModulus, big.NewInt(1))
	lowerBound := big.NewInt(int64(appleSRPByteLen * 16))
	for {
		secret, err := rand.Int(rand.Reader, max)
		if err != nil {
			return nil, err
		}
		if secret.Cmp(lowerBound) <= 0 {
			continue
		}
		public := new(big.Int).Exp(appleSRPGenerator, secret, appleSRPModulus)
		if public.Sign() > 0 {
			return &appleSRPSession{secret: secret, public: public}, nil
		}
	}
}

func (s *appleSRPSession) ClientEphemeral() []byte {
	return bytesFromBigInt(s.public)
}

func (s *appleSRPSession) Complete(username string, salt, derivedPassword, serverEphemeral []byte) (*appleSRPProofs, error) {
	B := new(big.Int).SetBytes(serverEphemeral)
	if B.Sign() <= 0 || B.Cmp(appleSRPModulus) >= 0 || new(big.Int).Mod(B, appleSRPModulus).Sign() == 0 {
		return nil, fmt.Errorf("server ephemeral is out of bounds")
	}

	k := hashToInt(bytesFromBigInt(appleSRPModulus), padSRP(appleSRPGenerator))
	inner := sha256Bytes(append([]byte{':'}, derivedPassword...))
	x := hashToInt(salt, inner)
	gPowX := new(big.Int).Exp(appleSRPGenerator, x, appleSRPModulus)

	kgx := new(big.Int).Mul(k, gPowX)
	kgx.Mod(kgx, appleSRPModulus)

	base := new(big.Int).Sub(B, kgx)
	base.Mod(base, appleSRPModulus)
	if base.Sign() == 0 {
		return nil, fmt.Errorf("invalid SRP shared-secret base")
	}

	paddedA := padSRP(s.public)
	A := bytesFromBigInt(s.public)
	u := hashToInt(paddedA, padSRP(B))
	if u.Sign() == 0 {
		return nil, fmt.Errorf("invalid SRP scrambling parameter")
	}

	ux := new(big.Int).Mul(u, x)
	exponent := new(big.Int).Add(s.secret, ux)
	sharedSecret := bytesFromBigInt(new(big.Int).Exp(base, exponent, appleSRPModulus))
	sessionKey := sha256Bytes(sharedSecret)

	hN := sha256Bytes(bytesFromBigInt(appleSRPModulus))
	hG := sha256Bytes(padSRP(appleSRPGenerator))
	xorNG := make([]byte, len(hN))
	for i := range hN {
		xorNG[i] = hN[i] ^ hG[i]
	}
	hUser := sha256Bytes([]byte(username))

	clientProof := sha256Bytes(xorNG, hUser, salt, A, bytesFromBigInt(B), sessionKey)
	serverProof := sha256Bytes(A, clientProof, sessionKey)
	return &appleSRPProofs{
		ClientProof: clientProof,
		ServerProof: serverProof,
		SessionKey:  sessionKey,
	}, nil
}

func padSRP(v *big.Int) []byte {
	out := v.Bytes()
	if len(out) >= appleSRPByteLen {
		return out
	}
	padded := make([]byte, appleSRPByteLen)
	copy(padded[appleSRPByteLen-len(out):], out)
	return padded
}

func bytesFromBigInt(v *big.Int) []byte {
	if v == nil {
		return nil
	}
	return v.Bytes()
}

func hashToInt(parts ...[]byte) *big.Int {
	return new(big.Int).SetBytes(sha256Bytes(parts...))
}

func sha256Bytes(parts ...[]byte) []byte {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write(part)
	}
	return h.Sum(nil)
}

func encryptPassword(password string, salt []byte, iterations int, protocol string) ([]byte, error) {
	if protocol != "s2k" && protocol != "s2k_fo" {
		return nil, fmt.Errorf("unsupported password protocol %q", protocol)
	}
	sum := sha256.Sum256([]byte(password))
	secret := sum[:]
	if protocol == "s2k_fo" {
		encoded := make([]byte, hex.EncodedLen(len(secret)))
		hex.Encode(encoded, secret)
		secret = encoded
	}
	return pbkdf2.Key(secret, salt, iterations, 32, sha256.New), nil
}

func decryptSPD(sessionKey, ciphertext []byte) ([]byte, error) {
	key := hmacSHA256(sessionKey, "extra data key:")
	iv := hmacSHA256(sessionKey, "extra data iv:")[:aes.BlockSize]
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("invalid SPD ciphertext length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	return pkcs7Unpad(plaintext, aes.BlockSize)
}

func hmacSHA256(key []byte, label string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(label))
	return mac.Sum(nil)
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, fmt.Errorf("invalid PKCS7 payload")
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > blockSize || padLen > len(data) {
		return nil, fmt.Errorf("invalid PKCS7 padding")
	}
	for _, b := range data[len(data)-padLen:] {
		if int(b) != padLen {
			return nil, fmt.Errorf("invalid PKCS7 padding")
		}
	}
	return data[:len(data)-padLen], nil
}
