package veracity

import (
	"fmt"

	"github.com/urfave/cli/v2"
)

func NewApp(version string, ikwid bool) *cli.App {

	cli.VersionPrinter = func(cCtx *cli.Context) {
		fmt.Println(cCtx.App.Version)
	}
	app := &cli.App{
		Name:    "veracity",
		Version: version,
		Usage:   "common read only operations on datatrails merklelog verifiable data",
		Description: "Veracity is a tool for verifying, forensically inspecting or efficiently replicating DataTrails transparency logs\n" +
			"Note the commands described below have further options which can be seen in the sub command --help output:\n" +
			"veracity [global options] command --help",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "loglevel", Value: "NOOP"},
			&cli.Int64Flag{Name: "height", Value: int64(defaultMassifHeight), Usage: "override the massif height"},
			&cli.StringFlag{
				Name: "data-url", Aliases: []string{"u"},
				Usage: "url to download merkle log data from. mutually exclusive with data-local; if neither option is supplied, DataTrails' live log data will be used",
			},
			&cli.StringFlag{
				Name: "data-local", Aliases: []string{"l"},
				Usage: "filesystem location to load merkle log data from. can be a directory of massifs or a single file. mutually exclusive with data-url; if neither option is supplied, DataTrails' live log data will be used",
			},
			&cli.StringFlag{
				Name: "tenant", Aliases: []string{"t"},
				Usage: "tenant or list of tenants as a `,` separated list. commands which operate on a single tenant take the first tenant in the list",
			},
		},
	}

	if ikwid {
		app.Flags = append(app.Flags, &cli.BoolFlag{
			Name: "envauth", Usage: "set to enable authorization from the environment (not all commands support this)",
		})
		app.Flags = append(app.Flags, &cli.StringFlag{
			Name: "account", Aliases: []string{"s"},
			Usage: fmt.Sprintf("the azure storage account. defaults to `%s' and triggers use of emulator url", AzuriteStorageAccount),
		})
		app.Flags = append(app.Flags, &cli.StringFlag{
			Name: "container", Aliases: []string{"c"},
			Usage: "the azure storage container. this is necessary when using the azurite storage emulator",
			Value: DefaultContainer,
		})
	}

	return app
}

func AddCommands(app *cli.App, ikwid bool) *cli.App {
	app.Commands = append(app.Commands, NewVerifyIncludedCmd())
	app.Commands = append(app.Commands, NewNodeCmd())
	app.Commands = append(app.Commands, NewLogWatcherCmd())
	app.Commands = append(app.Commands, NewReplicateLogsCmd())
	app.Commands = append(app.Commands, NewReceiptCmd())

	if ikwid {
		app.Commands = append(app.Commands, NewMassifsCmd())
		app.Commands = append(app.Commands, NewLogTailCmd())
		app.Commands = append(app.Commands, NewEventDiagCmd())
		app.Commands = append(app.Commands, NewDiagCmd())
		app.Commands = append(app.Commands, NewNodeScanCmd())
		app.Commands = append(app.Commands, NewFindTrieEntriesCmd())
		app.Commands = append(app.Commands, NewFindMMREntriesCmd())
		app.Commands = append(app.Commands, NewAppendCmd())
	}
	return app
}
