package main

import (
	"os"

	"github.com/pridhvi/mnemox/internal/app"
)

func main() {
	if err := app.New().Execute(); err != nil {
		os.Exit(1)
	}
}
