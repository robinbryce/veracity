package veracity

import (
	"fmt"
	"strings"

	"github.com/datatrails/go-datatrails-common/azblob"
	"github.com/urfave/cli/v2"
)

const (
	AzureBlobURLFmt       = "https://%s.blob.core.windows.net"
	AzuriteStorageAccount = "devstoreaccount1"
	DefaultContainer      = "merklelogs"
)

// cfgReader establishes the blob read only data accessor
// only azure blob storage is supported. Both emulated and production.
func cfgReader(cmd *CmdCtx, cCtx *cli.Context, forceProdUrl bool) (azblob.Reader, error) {
	var err error
	var reader azblob.Reader

	if cmd.log == nil {
		if err = cfgLogging(cmd, cCtx); err != nil {
			return nil, err
		}
	}

	// We prefer loading this from the command line argument, but if upstream code requests we default
	// to the production URL we inject that here.
	url := cCtx.String("data-url")
	if forceProdUrl {
		url = DefaultRemoteMassifURL
	}

	// These values are relevant for direct connection to Azure blob store (or emulator), but are
	// harmlessly irrelevant for standard remote connections that connect via public proxy. Potential
	// to simplify this function in future.
	container := cCtx.String("container")
	account := cCtx.String("account")
	envAuth := cCtx.Bool("envauth")

	if account == "" && url == "" {
		account = AzuriteStorageAccount
		cmd.log.Infof("defaulting to the emulator account %s", account)
	}

	if container == "" {
		container = DefaultContainer
		cmd.log.Infof("defaulting to the standard container %s", container)
	}

	if account == AzuriteStorageAccount {
		cmd.log.Infof("using the emulator and authorizing with the well known private key (for production no authorization is required)")
		// reader, err := azblob.NewAzurite(url, container)
		devCfg := azblob.NewDevConfigFromEnv()
		cmd.readerURL = devCfg.URL
		reader, err = azblob.NewDev(devCfg, container)
		if err != nil {
			return nil, err
		}
		return reader, nil
	}

	if url == "" {
		url = fmt.Sprintf(AzureBlobURLFmt, account)
	}
	if !strings.HasSuffix(url, "/") {
		url = url + "/"
	}

	if envAuth {
		devCfg := azblob.NewDevConfigFromEnv()
		cmd.readerURL = devCfg.URL
		reader, err = azblob.NewDev(devCfg, container)
		if err != nil {
			return nil, err
		}
		return reader, nil
	}

	cmd.readerURL = url
	reader, err = azblob.NewReaderNoAuth(cmd.log, url, azblob.WithContainer(container), azblob.WithAccountName(account))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to blob store: %v", err)
	}

	return reader, nil
}
