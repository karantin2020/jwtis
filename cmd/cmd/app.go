package cmd

import (
	"fmt"
	"os"

	cli "github.com/jawher/mow.cli"
)

/*
Cli represents the structure of a CLI app. It should be constructed using the App() function
*/
type Cli struct {
	cli               *cli.Cli
	cmd               *rootCmd
	name, version     string
	bucket, envPrefix string
}

/*
App creates a new and empty CLI app configured with the passed name and description.
name and description will be used to construct the help message for the app:
	Usage: $name [OPTIONS] COMMAND [arg...]
	$desc
*/
func App(name, desc string) *Cli {
	c := &Cli{
		cli: cli.App(name, desc),
		cmd: &rootCmd{
			name: name,
		},
	}
	c.name = name
	return c
}

/*
Config sets internal values
*/
func (c *Cli) Config(bucket, envPrefix string) {
	checkNilCli(c)
	if bucket == "" {
		fmt.Fprintf(os.Stderr, "empty bucket string")
		cli.Exit(1)
	}
	if envPrefix == "" {
		fmt.Fprintf(os.Stderr, "empty envPrefix string")
		cli.Exit(1)
	}
	c.bucket = bucket
	c.envPrefix = envPrefix
}

/*
Version sets the version string of the CLI app together with the options that can be used to trigger
printing the version string via the CLI.
	Usage: appName --$name
	$version
*/
func (c *Cli) Version(name, version string) {
	checkNilCli(c)
	c.cli.Version(name, version)
	c.version = version
	c.cmd.version = version
}

/*
Run uses the app configuration (specs, commands, ...) to parse the args slice
and to execute the matching command.
In case of an incorrect usage, and depending on the configured ErrorHandling policy,
it may return an error, panic or exit
*/
func (c *Cli) Run(args []string) error {
	checkNilCli(c)
	if c.bucket == "" {
		fmt.Fprintf(os.Stderr, "empty bucket string")
		cli.Exit(1)
	}
	if c.envPrefix == "" {
		fmt.Fprintf(os.Stderr, "empty envPrefix string")
		cli.Exit(1)
	}
	c.cmd.Register(c.cli, c.bucket, c.envPrefix)
	return c.cli.Run(args)
}

func checkNilCli(c *Cli) {
	if c == nil {
		fmt.Fprintf(os.Stderr, "nil pointer to Cli")
		cli.Exit(1)
	}
}
