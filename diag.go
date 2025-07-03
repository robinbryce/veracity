package veracity

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/datatrails/go-datatrails-merklelog/massifs"
	"github.com/datatrails/go-datatrails-merklelog/massifs/snowflakeid"
	"github.com/datatrails/go-datatrails-merklelog/mmr"
	"github.com/urfave/cli/v2"
)

// NewDiagCmd prints diagnostic information about the massif blob containg a
// specific mmrIndex
func NewDiagCmd() *cli.Command {
	return &cli.Command{Name: "diag",
		Usage: "print diagnostics about a blob identified by massif index or by an mmrindex",
		Flags: []cli.Flag{
			&cli.Uint64Flag{
				Name: "mmrindex", Aliases: []string{"i"},
			},
			&cli.Int64Flag{
				Name: "massif", Aliases: []string{"m"},
				Usage: "allow inspection of an arbitrary mmr index by explicitly specifying a massif index",
				Value: -1,
			},
		},
		Action: func(cCtx *cli.Context) error {
			var err error

			cmd := &CmdCtx{}
			if err = cfgMassifReader(cmd, cCtx); err != nil {
				return err
			}
			if cmd.massifHeight == 0 {
				return fmt.Errorf("massif height can't be zero")
			}

			fmt.Printf("%8d trie-header-start\n", massifs.TrieHeaderStart())
			fmt.Printf("%8d trie-data-start\n", massifs.TrieDataStart())
			fmt.Printf("%8d peak-stack-start\n", massifs.PeakStackStart(cmd.massifHeight))

			// support identifying the massif implicitly via the index of a log
			// entry. note that mmrIndex 0 is just handled as though the caller
			// asked for massifIndex 0
			mmrIndex := cCtx.Uint64("mmrindex")
			signedMassifIndex := cCtx.Int64("massif")
			massifIndex := uint64(signedMassifIndex)
			if mmrIndex > uint64(0) && signedMassifIndex == -1 {
				massifIndex = massifs.MassifIndexFromMMRIndex(cmd.massifHeight, mmrIndex)
			}
			fmt.Printf("%8d peak-stack-len\n", massifs.PeakStackLen(massifIndex))
			logStart := massifs.PeakStackEnd(massifIndex, cmd.massifHeight)
			fmt.Printf("%8d tree-start\n", logStart)
			fmt.Printf("%8d massif\n", massifIndex)
			if mmrIndex > 0 {
				fmt.Printf("%8d mmrindex\n", mmrIndex)
			}
			if cCtx.Bool("noread") {
				return nil
			}
			if err = cfgMassifReader(cmd, cCtx); err != nil {
				return err
			}
			tenant := cCtx.String("tenant")
			if tenant == "" && !cCtx.IsSet("data-local") {
				fmt.Println("a tenant is required to get diagnostics that require reading a blob")
				return nil
			}
			cmd.massif, err = cmd.massifReader.GetMassif(context.Background(), tenant, massifIndex)
			if err != nil {
				return err
			}
			fmt.Printf("%8d start:massif-height\n", cmd.massif.Start.MassifHeight)
			fmt.Printf("%8d start:data-epoch\n", cmd.massif.Start.DataEpoch)
			fmt.Printf("%8d start:commitment-epoch\n", cmd.massif.Start.CommitmentEpoch)
			fmt.Printf("%8d start:first-index\n", cmd.massif.Start.FirstIndex)
			fmt.Printf("%8d start:peak-stack-len\n", cmd.massif.Start.PeakStackLen)

			fmt.Printf("%8d count\n", cmd.massif.Count())
			fmt.Printf("%8d leaf-count\n", cmd.massif.MassifLeafCount())
			fmt.Printf("%8d last-leaf-mmrindex\n", cmd.massif.LastLeafMMRIndex())

			// trieIndex is equivilent to leafIndex, but we use the term trieIndex
			//  when dealing with trie data.
			trieIndex := mmr.LeafIndex(mmrIndex)
			fmt.Printf("%8d trie-index\n", trieIndex)

			// FirstIndex is the *size* of the mmr preceding the current massif
			expectTrieIndexMassif := trieIndex - mmr.LeafCount(cmd.massif.Start.FirstIndex)
			fmt.Printf("%8d trie-index - massif-first-index\n", expectTrieIndexMassif)

			logTrieKey, err := cmd.massif.GetTrieKey(mmrIndex)
			if err != nil {
				return fmt.Errorf("when expecting %d for %d: %v", expectTrieIndexMassif, mmrIndex, err)
			}
			logTrieEntry, err := cmd.massif.GetTrieEntry(mmrIndex)
			if err != nil {
				entryIndex := mmr.LeafIndex(mmrIndex)
				// FirstIndex is the *size* of the mmr preceding the current massif
				expectTrieIndexMassif := entryIndex - mmr.LeafCount(cmd.massif.Start.FirstIndex)
				return fmt.Errorf("when expecting %d for %d: %v", expectTrieIndexMassif, mmrIndex, err)
			}

			logNodeValue, err := cmd.massif.Get(mmrIndex)
			if err != nil {
				return err
			}
			fmt.Printf("%x log-value\n", logNodeValue)

			idBytes := logTrieKey[massifs.TrieEntryIdTimestampStart:massifs.TrieEntryIdTimestampEnd]
			id := binary.BigEndian.Uint64(idBytes)
			unixMS, err := snowflakeid.IDUnixMilli(id, uint8(cmd.massif.Start.CommitmentEpoch))
			if err != nil {
				return err
			}
			idTime := time.UnixMilli(unixMS)
			fmt.Printf("%x log-trie-key\n", logTrieKey[:32])
			fmt.Printf("%x %s\n", logTrieKey[32:], idTime.Format(time.DateTime))
			fmt.Printf("%x log-trie-entry\n", logTrieEntry[:64])

			return nil
		},
	}
}
