package main

import (
	"fmt"
	"log"
	"os"

	// "strings"

	"github.com/datatrails/veracity"
)

// Note: the ci does the right thing with go-releaser automatically, as
// configured in the repo's .goreleaser.yml file.
// Also, task build:fast sets the ldflags correctly for the version, commit, and
// build date so it is clear if a developer build is used.
var (
	version   string
	commit    string
	buildDate string
)

func main() {

	versionString := "unknown"
	if version != "" {
		// versionString = fmt.Sprintf("%s %s %s", version, commit, buildDate)
		versionString = fmt.Sprintf("%s %s", version, commit)
	}

	ikwid := true
	// envikwid := os.Getenv("VERACITY_IKWID")
	// if envikwid == "1" || strings.ToLower(envikwid) == "true" {
	// 	ikwid = true
	// }
	app := veracity.NewApp(versionString, ikwid)
	veracity.AddCommands(app, ikwid)
	if err := app.Run(os.Args); err != nil {
		fmt.Printf("error: %v\n", err)
		log.Fatal(err)
	}
}
