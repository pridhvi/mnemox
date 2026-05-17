package main

import (
	"os"

	"mnemox/internal/app"
)

func main() {
	if err := app.New().Execute(); err != nil {
		os.Exit(1)
	}
}
