package veracity

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"

	dtcose "github.com/datatrails/go-datatrails-common/cose"
	"github.com/fxamacker/cbor/v2"
)

const (
	ECDSAPublicDefaultPEMFileName  = "ecdsa-key-public.pem"
	ECDSAPrivateDefaultPEMFileName = "ecdsa-key-private.pem"
	ECDSAPublicDefaultFileName     = "ecdsa-key-public.cbor"
	ECDSAPrivateDefaultFileName    = "ecdsa-key-private.cbor"
	ECDSAPrivateDefaultPerm        = 0600 // Default permission for private key file
	ECDSAPublicDefaultPerm         = 0644 // Default permission for private key file
)

func ReadECDSAPublicCose(
	fileName string,
	expectedStandardCurve ...string,
) (*ecdsa.PublicKey, error) {
	// Read the public key from the default file
	data, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	publicKey, err := decodeECDSAPublicKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	if len(expectedStandardCurve) > 0 &&
		publicKey.Params().Name != expectedStandardCurve[0] {
		return nil, fmt.Errorf("expected ECDSA public key with curve %s, got %s",
			expectedStandardCurve[0], publicKey.Curve.Params().Name)
	}

	return publicKey, nil
}

func ReadECDSAPrivateCose(
	fileName string,
	expectedStandardCurve ...string,
) (*ecdsa.PrivateKey, error) {
	// Read the private key from the default file
	data, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}
	privateKey, err := decodeECDSAPrivateKey(data, expectedStandardCurve...)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}
	if len(expectedStandardCurve) > 0 &&
		privateKey.PublicKey.Params().Name != expectedStandardCurve[0] {
		return nil, fmt.Errorf("expected ECDSA private key with curve %s, got %s",
			expectedStandardCurve[0], privateKey.PublicKey.Curve.Params().Name)
	}
	return privateKey, nil
}

func ReadECDSAPrivatePEM(filePath string) (*ecdsa.PrivateKey, error) {
	pemData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, errors.New("invalid PEM block or type")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// Serializes the key to PEM format
func encodeECDSAPrivateKeyToPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}
	return pem.EncodeToMemory(block), nil
}

// Writes PEM to a file with 0600 permissions
func WriteECDSAPrivatePEM(pemFile string, key *ecdsa.PrivateKey) error {
	pemBytes, err := encodeECDSAPrivateKeyToPEM(key)
	if err != nil {
		return fmt.Errorf("PEM encoding failed: %w", err)
	}
	return os.WriteFile(pemFile, pemBytes, 0600)
}

func WriteECDSAPublicCOSE(
	pubFile string,
	publicKey *ecdsa.PublicKey,
) (string, error) {

	var err error

	if _, err = writeCoseECDSAPublicKey(pubFile, publicKey); err != nil {
		return "", err
	}
	return pubFile, nil
}

func WriteECDSAPrivateCOSE(
	privFile string,
	privateKey *ecdsa.PrivateKey,
) (string, error) {

	var err error

	if _, err = writeCoseECDSAPrivateKey(privFile, privateKey); err != nil {
		return "", err
	}
	return privFile, nil
}

// Encode private key to COSE_Key format (as CBOR bytes)
func encodePrivateKeyToCOSE(key *ecdsa.PrivateKey) ([]byte, error) {
	m := map[int]interface{}{
		dtcose.KeyTypeLabel:   int64(dtcose.KeyTypeEC2),
		dtcose.AlgorithmLabel: -7, // ES256 (ECDSA w/ SHA-256)
		dtcose.ECCurveLabel:   1,  // P-256
		dtcose.ECXLabel:       key.PublicKey.X.Bytes(),
		dtcose.ECYLabel:       key.PublicKey.Y.Bytes(),
		dtcose.ECDLabel:       key.D.Bytes(),
	}
	return cbor.Marshal(m)
}

// Encode public key to COSE_Key format (as CBOR bytes)
func encodePublicKeyToCOSE(key *ecdsa.PublicKey) ([]byte, error) {
	m := map[int]interface{}{
		dtcose.KeyTypeLabel:   int64(dtcose.KeyTypeEC2),
		dtcose.AlgorithmLabel: -7, // ES256 (ECDSA w/ SHA-256)
		dtcose.ECCurveLabel:   1,  // P-256
		dtcose.ECXLabel:       key.X.Bytes(),
		dtcose.ECYLabel:       key.Y.Bytes(),
	}
	return cbor.Marshal(m)
}

func decodeECDSAPrivateKey(
	data []byte,
	expectedStandardCurve ...string,
) (*ecdsa.PrivateKey, error) {
	var m map[int64]interface{}
	if err := cbor.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	publicKey, err := decodeECDSAPublicKeyFromMap(m, expectedStandardCurve...)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key from map: %w", err)
	}

	d := big.NewInt(0)
	d.SetBytes(m[dtcose.ECDLabel].([]byte))

	privateKey := &ecdsa.PrivateKey{
		PublicKey: *publicKey,
		D:         d,
	}
	return privateKey, nil
}

func decodeECDSAPublicKey(
	data []byte,
	expectedStandardCurve ...string,
) (*ecdsa.PublicKey, error) {

	var m map[int64]interface{}
	if err := cbor.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return decodeECDSAPublicKeyFromMap(m, expectedStandardCurve...)
}

func decodeECDSAPublicKeyFromMap(
	m map[int64]interface{},
	expectedStandardCurve ...string,
) (*ecdsa.PublicKey, error) {

	ecKey, err := dtcose.NewECCoseKey(m)
	genericKey, err := ecKey.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key from COSE key: %w", err)
	}

	publicKey, ok := genericKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected ECDSA public key, got %T", genericKey)
	}

	if len(expectedStandardCurve) > 0 &&
		publicKey.Params().Name != expectedStandardCurve[0] {
		return nil, fmt.Errorf("expected ECDSA public key with curve %s, got %s",
			expectedStandardCurve[0], publicKey.Curve.Params().Name)
	}

	return publicKey, nil
}

func writeCoseECDSAPrivateKey(
	fileName string,
	privateKey *ecdsa.PrivateKey,
	perms ...os.FileMode,
) ([]byte, error) {

	var err error
	var data []byte
	if data, err = encodePrivateKeyToCOSE(privateKey); err != nil {
		return nil, err
	}

	perm := os.FileMode(ECDSAPrivateDefaultPerm) // Default permission
	if len(perms) > 0 {
		perm = perms[0]
	}

	// Save to file
	if err := os.WriteFile(fileName, data, perm); err != nil {
		return nil, err
	}
	return data, nil
}

func writeCoseECDSAPublicKey(
	fileName string,
	publicKey *ecdsa.PublicKey,
	perms ...os.FileMode,
) ([]byte, error) {

	var err error
	var data []byte
	if data, err = encodePublicKeyToCOSE(publicKey); err != nil {
		return nil, err
	}

	perm := os.FileMode(ECDSAPublicDefaultPerm) // Default permission
	if len(perms) > 0 {
		perm = perms[0]
	}

	// Save to file
	if err := os.WriteFile(fileName, data, perm); err != nil {
		return nil, err
	}
	return data, nil
}
