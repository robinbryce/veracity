package veracity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	dtcose "github.com/datatrails/go-datatrails-common/cose"
	"github.com/datatrails/go-datatrails-common/logger"
	"github.com/datatrails/go-datatrails-merklelog/massifs"
	"github.com/datatrails/go-datatrails-merklelog/massifs/snowflakeid"
	"github.com/datatrails/go-datatrails-merklelog/mmr"
	"github.com/urfave/cli/v2"
)

// coseSigner implements IdentifiableCoseSigner
type identifiableCoseSigner struct {
	innerSigner cose.Signer
	publicKey   ecdsa.PublicKey
}

func (s *identifiableCoseSigner) Algorithm() cose.Algorithm {
	return s.innerSigner.Algorithm()
}

func (s *identifiableCoseSigner) Sign(rand io.Reader, content []byte) ([]byte, error) {
	return s.innerSigner.Sign(rand, content)
}

func (s *identifiableCoseSigner) LatestPublicKey() (*ecdsa.PublicKey, error) {
	return &s.publicKey, nil
}

func (s *identifiableCoseSigner) PublicKey(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	return &s.publicKey, nil
}

func (s *identifiableCoseSigner) KeyLocation() string {
	return "robinbryce.me"
}

func (s *identifiableCoseSigner) KeyIdentifier() string {

	// the returned kid needs to match the kid format of the keyvault key
	return "location:robinbryce/version1"
}

// NewAppendCmd appends an entry to a local ledger, optionally sealing it with a provided private key.
func NewAppendCmd() *cli.Command {
	return &cli.Command{Name: "append",
		Usage: "add an entry to a local ledger, optionally sealing it with a provided private key",
		Flags: []cli.Flag{
			&cli.Uint64Flag{
				Name: "mmrindex", Aliases: []string{"i"},
			},
			&cli.Int64Flag{
				Name: "massif", Aliases: []string{"m"},
				Usage: "allow inspection of an arbitrary mmr index by explicitly specifying a massif index",
				Value: -1,
			},
			&cli.StringFlag{
				Name:  "sealer-key",
				Usage: "the sealer key to use for signing the entry, in cose .cbor. Only P-256, ES256 is supported. If --generate-sealer-key is set, this generated key will be written to this file.",
			},
			&cli.StringFlag{
				Name: "trusted-sealer-key-pem", Aliases: []string{"s"},
				Usage: "verify the current seal using this pem file based public key",
			},

			&cli.StringFlag{
				Name: "receipt-file", Aliases: []string{"f"},
				Usage: "file name to write the receipt to, defaults to 'receipt-{mmrIndex}.cbor'",
			},

			&cli.BoolFlag{
				Name: "generate-sealer-key", Aliases: []string{"g"},
				Usage: "generate a new sealer key and write it to the sealer-key file. If the sealer-key file already exists, it will be overwritten. the default file name is 'ecdsa-key-private.cbor'.",
			},
		},
		Action: func(cCtx *cli.Context) error {
			var err error

			if !cCtx.IsSet("data-local") {
				return errors.New("this command supports local replicas only, and requires --data-local")
			}

			idState, err := snowflakeid.NewIDState(snowflakeid.Config{
				CommitmentEpoch: 1,
				WorkerCIDR:      "0.0.0.0/16",
				PodIP:           "10.0.0.1",
			})
			if err != nil {
				return fmt.Errorf("failed to create snowflake id state: %w", err)
			}

			idTimestamp, err := idState.NextID()
			if err != nil {
				return fmt.Errorf("failed to generate snowflake id: %w", err)
			}

			hasher := sha256.New()
			hasher.Write(AmourySignedStatement)
			// Take the first 24 bytes of the hash as the extra bytes
			statementHash := hasher.Sum(nil)
			extraBytes := statementHash[:expectedExtraBytesSize]
			leafHash, err := mmrEntryVersion1(extraBytes, idTimestamp, AmourySignedStatement)
			if err != nil {
				return fmt.Errorf("failed to create mmr entry: %w", err)
			}
			fmt.Printf("%x statement-hash\n", statementHash)
			fmt.Printf("%x leaf-hash\n", leafHash)

			cmd := &CmdCtx{}

			if err = cfgMassifReader(cmd, cCtx); err != nil {
				return err
			}
			tenant := cCtx.String("tenant")
			if tenant == "" {
				fmt.Println("a tenant is required")
				return nil
			}

			if cmd.cborCodec, err = massifs.NewRootSignerCodec(); err != nil {
				return err
			}

			cache, err := massifs.NewLogDirCache(cmd.log, NewFileOpener())
			if err != nil {
				return err
			}
			reader, err := massifs.NewLocalReader(logger.Sugar, cache)
			if err != nil {
				return err
			}

			opts := []massifs.DirCacheOption{
				// massifs.WithDirCacheReplicaDir(cCtx.String("replicadir")),
				// massifs.WithDirCacheReplicaDir(cCtx.String("data-local")),
				massifs.WithDirCacheMassifLister(NewDirLister()),
				massifs.WithDirCacheSealLister(NewDirLister()),
				massifs.WithReaderOption(massifs.WithMassifHeight(uint8(cmd.massifHeight))),
				massifs.WithReaderOption(massifs.WithSealGetter(&reader)),
				massifs.WithReaderOption(massifs.WithCBORCodec(cmd.cborCodec)),
			}

			// This will require that the remote seal is signed by the key
			// provided here. If it is not, even if the seal is valid, the
			// verification will fail with a suitable error.
			pemString := cCtx.String("trusted-sealer-key-pem")
			if pemString != "" {
				pem, err := DecodeECDSAPublicString(pemString)
				if err != nil {
					return err
				}
				opts = append(opts, massifs.WithReaderOption(massifs.WithTrustedSealerPub(pem)))
			}

			// For the localreader, the seal getter is the local reader itself.
			// So we need to make use of ReplaceOptions on the cache, so we can
			// provide the options after we have created the local reader.
			cache.ReplaceOptions(opts...)

			verified, err := reader.GetHeadVerifiedContext(context.Background(), tenant)
			if err != nil {
				return err
			}

			mmrSizeLast := verified.RangeCount()
			fmt.Printf("%8d verified-size\n", mmrSizeLast)
			verified.Tags = map[string]string{}
			mmrIndex, err := verified.AddHashedLeaf(sha256.New(), idTimestamp, extraBytes, leafHash, []byte("scitt"), leafHash)
			if err != nil {
				return fmt.Errorf("failed to add hashed leaf: %w", err)
			}
			fmt.Printf("%8d mmrindex\n", mmrIndex)
			// verified.CommitContext()

			var sealingKey *ecdsa.PrivateKey
			if cCtx.IsSet("sealer-key") && !cCtx.Bool("generate-sealer-key") {
				sealerKeyFile := cCtx.String("sealer-key")
				if sealerKeyFile == "" {
					return errors.New("sealer-key file is required")
				}
				sealingKey, err = ReadECDSAPrivateCose(sealerKeyFile, "P-256")
				if err != nil {
					return fmt.Errorf("failed to load sealer key from file %s: %w", sealerKeyFile, err)
				}
			}
			if cCtx.IsSet("sealer-key-pem") && !cCtx.Bool("generate-sealer-key") {
				if cCtx.IsSet("sealer-key") {
					fmt.Printf("verifying with sealer-key-pem %s (in preference to sealer-key)", cCtx.String("sealer-key-pem"))
				}
				sealerKeyFile := cCtx.String("sealer-key-pem")
				if sealerKeyFile == "" {
					return errors.New("sealer-key file is required")
				}
				sealingKey, err = ReadECDSAPrivatePEM(sealerKeyFile)
				if err != nil {
					return fmt.Errorf("failed to load sealer key from file %s: %w", sealerKeyFile, err)
				}
			}

			if cCtx.Bool("generate-sealer-key") {
				sealingKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					return err
				}
			}

			alg, err := dtcose.CoseAlgForEC(sealingKey.PublicKey)
			if err != nil {
				return err
			}

			coseSigner, err := cose.NewSigner(alg, sealingKey)
			if err != nil {
				return err
			}
			identifiableSigner := &identifiableCoseSigner{
				innerSigner: coseSigner,
				publicKey:   sealingKey.PublicKey,
			}

			rootSigner := massifs.NewRootSigner("https://github.com/robinbryce/veracity", cmd.cborCodec)

			// TODO: account for filling a massif
			mmrSizeCurrent := verified.RangeCount()
			cp, err := mmr.IndexConsistencyProof(&verified.MassifContext, verified.MMRState.MMRSize-1, mmrSizeCurrent-1)
			ok, peaksB, err := mmr.CheckConsistency(
				verified, sha256.New(),
				cp.MMRSizeA, cp.MMRSizeB, verified.MMRState.Peaks)
			if !ok {
				return fmt.Errorf("consistency check failed: verifie failed")
			}
			if err != nil {
				return err
			}
			lastIdTimestamp := verified.GetLastIdTimestamp()

			state := massifs.MMRState{
				Version:         int(massifs.MMRStateVersionCurrent),
				MMRSize:         mmrSizeCurrent,
				Peaks:           peaksB,
				Timestamp:       time.Now().UnixMilli(),
				CommitmentEpoch: verified.MMRState.CommitmentEpoch,
				IDTimestamp:     lastIdTimestamp,
			}
			subject := massifs.TenantMassifBlobPath(tenant, uint64(verified.Start.MassifIndex))
			publicKey, err := identifiableSigner.LatestPublicKey()
			if err != nil {
				return fmt.Errorf("unable to get public key for signing key %w", err)
			}

			keyIdentifier := identifiableSigner.KeyIdentifier()
			data, err := rootSigner.Sign1(coseSigner, keyIdentifier, publicKey, subject, state, nil)
			if err != nil {
				return err
			}

			// note that state is not verified here, but we just signed it so it is our droid
			msg, state, err := massifs.DecodeSignedRoot(cmd.cborCodec, data)
			if err != nil {
				return err
			}

			// this is a slightly tweaked variant of massifs.NewReceipt (go-datatrails-merklelog/massifs/mmriver.go)

			// because we added a single leaf, the size pre-add is the mmrIndex of the next leaf.
			newStatementMMRIndex := verified.MMRState.MMRSize
			proof, err := mmr.InclusionProof(&verified.MassifContext, state.MMRSize-1, newStatementMMRIndex)
			if err != nil {
				return fmt.Errorf(
					"failed to generating inclusion proof: %d in MMR(%d), %v",
					newStatementMMRIndex, verified.MMRState.MMRSize, err)
			}

			peakIndex := mmr.PeakIndex(mmr.LeafCount(state.MMRSize), len(proof))
			// NOTE: The old-accumulator compatibility property, from
			// https://eprint.iacr.org/2015/718.pdf, along with the COSE protected &
			// unprotected buckets, is why we can just pre sign the receipts.
			// As long as the receipt consumer is convinced of the logs consistency (not split view),
			// it does not matter which accumulator state the receipt is signed against.

			var peaksHeader massifs.MMRStateReceipts
			err = cbor.Unmarshal(msg.Headers.RawUnprotected, &peaksHeader)
			if err != nil {
				return fmt.Errorf(
					"%w: failed decoding peaks header", err)
			}
			if peakIndex >= len(peaksHeader.PeakReceipts) {
				return fmt.Errorf(
					"%w: peaks header contains to few peak receipts", err)
			}

			// This is an array of marshaled COSE_Sign1's
			receiptMsg := peaksHeader.PeakReceipts[peakIndex]
			signed, err := dtcose.NewCoseSign1MessageFromCBOR(
				receiptMsg, dtcose.WithDecOptions(massifs.CheckpointDecOptions()))
			if err != nil {
				return fmt.Errorf(
					"%w: failed to decode pre-signed receipt for: %d in MMR(%d)",
					err, mmrIndex, state.MMRSize)
			}

			// signed.Headers.RawProtected = nil
			signed.Headers.RawUnprotected = nil

			verifiableProofs := massifs.MMRiverVerifiableProofs{
				InclusionProofs: []massifs.MMRiverInclusionProof{{
					Index:         mmrIndex,
					InclusionPath: proof}},
			}

			signed.Headers.Unprotected[massifs.VDSCoseReceiptProofsTag] = verifiableProofs

			receiptCbor, err := signed.MarshalCBOR()
			if err != nil {
				return fmt.Errorf("failed to marshal receipt: %w", err)
			}

			receiptFileName := cCtx.String("receipt-file")
			if receiptFileName == "" {
				receiptFileName = fmt.Sprintf("receipt-%d.cbor", newStatementMMRIndex)
			}
			if err := os.WriteFile(receiptFileName, receiptCbor, os.FileMode(0644)); err != nil {
				return fmt.Errorf("failed to write receipt file %s: %w", receiptFileName, err)
			}
			fmt.Printf("wrote receipt file %s\n", receiptFileName)

			forkFileName := filepath.Join(".", fmt.Sprintf("fork-%d-%d.bin", verified.MMRState.MMRSize-1, mmrSizeCurrent))
			if err := os.WriteFile(forkFileName, data, os.FileMode(0644)); err != nil {
				return fmt.Errorf("failed to write log fork file %s: %w", forkFileName, err)
			}
			fmt.Printf("wrote forked log massif file %s\n", forkFileName)

			checkpointFileName := filepath.Join(".", fmt.Sprintf("checkpoint-%d.cbor", mmrSizeCurrent))
			if err := os.WriteFile(checkpointFileName, data, os.FileMode(0644)); err != nil {
				return fmt.Errorf("failed to write checkpoint file %s: %w", checkpointFileName, err)
			}
			fmt.Printf("wrote checkpoint file %s\n", checkpointFileName)
			if cCtx.Bool("generate-sealer-key") {
				// write the sealer key to the sealer-key file
				sealerKeyFile := cCtx.String("sealer-key")
				if sealerKeyFile == "" {
					sealerKeyFile = ECDSAPrivateDefaultFileName
				}
				if _, err := WriteECDSAPrivateCOSE(sealerKeyFile, sealingKey); err != nil {
					return fmt.Errorf("failed to write sealer key to file %s: %w", sealerKeyFile, err)
				}
				fmt.Printf("wrote sealer key to file %s\n", sealerKeyFile)
				sealerKeyFile = cCtx.String("sealer-key-pem")
				if sealerKeyFile == "" {
					sealerKeyFile = ECDSAPrivateDefaultPEMFileName
				}
				if err := WriteECDSAPrivatePEM(sealerKeyFile, sealingKey); err != nil {
					return fmt.Errorf("failed to write sealer key to file %s: %w", sealerKeyFile, err)
				}
				fmt.Printf("wrote sealer key to file %s\n", sealerKeyFile)
				if _, err := writeCoseECDSAPublicKey(sealerKeyFile, &sealingKey.PublicKey); err != nil {
					return fmt.Errorf("failed to write sealer key to file %s: %w", sealerKeyFile, err)
				}
				fmt.Printf("wrote sealer key to file %s\n", sealerKeyFile)

			}
			return nil
		},
	}
}

const (
	expectedExtraBytesSize = 24
)

// mmrEntryVersion1 gets the mmr entry for log entry version 1.
//
// mmr entry format for log entry version 1:
//
// H( domain | mmrSalt | serializedBytes )
//
// where mmrSalt = extraBytes + idtimestamp
//
// NOTE: extraBytes is consistently 24 bytes on the trie value, so we pad/truncate extrabytes here
// to ensure its 24 bytes also. This allows greater consistency and ease of moving between mmrSalt and trieValue
func mmrEntryVersion1(extraBytes []byte, idtimestamp uint64, serializedBytes []byte) ([]byte, error) {

	hasher := sha256.New()

	// domain
	hasher.Write([]byte{byte(LeafTypePlain)})

	// mmrSalt

	// ensure extrabytes is 24 bytes long
	extraBytes, err := consistentExtraBytesSize(extraBytes)
	if err != nil {
		return nil, err
	}
	hasher.Write(extraBytes)

	// convert idtimestamp to bytes
	idTimestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(idTimestampBytes, idtimestamp)
	hasher.Write(idTimestampBytes)

	// serializedBytes
	hasher.Write(serializedBytes)

	return hasher.Sum(nil), nil
}

// consistentExtraBytesSize ensures the given extraBytes is padded/truncated to exactly 24 bytes
func consistentExtraBytesSize(extraBytes []byte) ([]byte, error) {

	extraBytesSize := len(extraBytes)

	// larger size need to truncate
	if extraBytesSize > expectedExtraBytesSize {
		return nil, errors.New("extra bytes is too large, maximum extra bytes size is 24")
	}

	// smaller size need to pad
	if extraBytesSize < expectedExtraBytesSize {
		tmp := make([]byte, expectedExtraBytesSize)
		copy(tmp[:extraBytesSize], extraBytes)
		return tmp, nil
	}

	// goldilocks just right
	return extraBytes, nil
}
