package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula"
)

// A version string that can be set with
//
//     -ldflags "-X main.Build=SOMEVERSION"
//
// at compile-time.
var Build string

func main() {
	fs := flag.NewFlagSet("nebula", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to either a file or directory to load configuration from")
	configTest := fs.Bool("test", false, "Test the config and print the end result. Non zero exit indicates a faulty config")
	printVersion := fs.Bool("version", false, "Print version")
	printUsage := fs.Bool("help", false, "Print command line usage")

	fs.Parse(os.Args[1:])

	if *printVersion {
		fmt.Printf("Version: %s\n", Build)
		os.Exit(0)
	}

	if *printUsage {
		fs.Usage()
		os.Exit(0)
	}

	if *configPath == "" {
		fmt.Println("-config flag must be set")
		fs.Usage()
		os.Exit(1)
	}

	l := logrus.New()
	l.Out = os.Stdout

	config := nebula.NewConfig(l)
	err := config.Load(*configPath)
	if err != nil {
		fmt.Printf("failed to load config: %s", err)
		os.Exit(1)
	}

	c, err := nebula.Main(config, *configTest, Build, l, nil)

	switch v := err.(type) {
	case nebula.ContextualError:
		v.Log(l)
		os.Exit(1)
	case error:
		l.WithError(err).Error("Failed to start")
		os.Exit(1)
	}

	if !*configTest {
		c.Start()
		c.ShutdownBlock()
	}

	os.Exit(0)
}
