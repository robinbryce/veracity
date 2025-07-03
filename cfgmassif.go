package veracity

import (
	"context"
	"fmt"

	"github.com/datatrails/go-datatrails-common/logger"
	"github.com/datatrails/go-datatrails-merklelog/massifs"
	"github.com/urfave/cli/v2"
)

const (
	defaultMassifHeight = uint8(14)
)

// cfgMassifReader establishes the blob read only data accessor
// only azure blob storage is supported. Both emulated and produciton.
func cfgMassifReader(cmd *CmdCtx, cCtx *cli.Context) error {

	var err error
	if cmd.log == nil {
		if err = cfgLogging(cmd, cCtx); err != nil {
			return err
		}
	}

	cmd.massifHeight = uint8(cCtx.Uint("height"))
	if cmd.massifHeight == 0 {
		cmd.massifHeight = defaultMassifHeight
	}

	localLog := cCtx.String("data-local")
	remoteLog := cCtx.String("data-url")

	if localLog != "" && remoteLog != "" {
		return fmt.Errorf("can't use data-local and data-url at the same time")
	}

	if localLog == "" && remoteLog == "" {
		// If we had no url and no local data supplied we default to the production data source.
		reader, err := cfgReader(cmd, cCtx, true)
		if err != nil {
			return err
		}
		mr := massifs.NewMassifReader(logger.Sugar, reader)
		cmd.massifReader = &mr

	} else if localLog != "" {

		codec, err := massifs.NewRootSignerCodec()
		if err != nil {
			return err
		}

		// This configures the dir cache and local reader for single tenant use,
		// InReplicaMode is false, meaning tenant specific filesystem paths are
		// not automatically derived.
		cache, err := massifs.NewLogDirCache(
			logger.Sugar,
			NewFileOpener(),
			massifs.WithDirCacheTenant(cCtx.String("tenant")),
			// massifs.WithExplicitFilePaths(cCtx.String("tenant")), // may be empty string
			massifs.WithDirCacheMassifLister(NewDirLister()),
			massifs.WithDirCacheSealLister(NewDirLister()),
			massifs.WithReaderOption(massifs.WithMassifHeight(cmd.massifHeight)),
			massifs.WithReaderOption(massifs.WithCBORCodec(codec)),
		)
		if err != nil {
			return err
		}

		mr, err := massifs.NewLocalReader(logger.Sugar, cache)
		if err != nil {
			return err
		}
		cmd.massifReader = &mr

	} else {
		// otherwise configure for reading from remote blobs
		reader, err := cfgReader(cmd, cCtx, false)
		if err != nil {
			return err
		}
		mr := massifs.NewMassifReader(logger.Sugar, reader)
		cmd.massifReader = &mr
	}

	return nil
}

// cfgMassif configures a massif reader and reads a massif
func cfgMassif(cmd *CmdCtx, cCtx *cli.Context) error {
	var err error

	if err = cfgMassifReader(cmd, cCtx); err != nil {
		return err
	}

	tenant := CtxGetOneTenantOption(cCtx)
	if tenant == "" {
		return fmt.Errorf("tenant must be provided for this command")
	}

	ctx := context.Background()

	mmrIndex := cCtx.Uint64("mmrindex")
	massifIndex := cCtx.Uint64("massif")

	// mmrIndex zero is always going to be massifIndex 0 so we treat this the
	// same as though the massif option had been supplied as 0
	if massifIndex == uint64(0) && mmrIndex == uint64(0) {
		cmd.massif, err = cmd.massifReader.GetMassif(context.Background(), tenant, massifIndex)
		return err
	}

	// now, if we have a non zero mmrIndex, use it to (re)compute the massifIndex
	if mmrIndex > uint64(0) {
		massifIndex = massifs.MassifIndexFromMMRIndex(cmd.massifHeight, mmrIndex)

		cmd.massif, err = cmd.massifReader.GetMassif(context.Background(), tenant, massifIndex)
		return err
	}

	// If massifIndex is not provided it will be zero here, and that is a good
	// default.
	massif, err := cmd.massifReader.GetMassif(ctx, tenant, massifIndex)
	if err != nil {
		return err
	}
	cmd.massif = massif
	return nil
}
