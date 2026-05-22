package console

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/chzyer/readline"
	"github.com/google/shlex"
	"golang.org/x/term"
)

type ExecuteFunc func(args []string) error

func Run(exec ExecuteFunc, vaultPath string) error {
	rl, err := readline.NewEx(&readline.Config{
		Prompt:          "mnemox > ",
		HistoryFile:     historyFile(),
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if err != nil {
		return err
	}
	defer rl.Close()

	fmt.Println("Mnemox console. Type 'help' for commands, 'exit' to quit.")
	for {
		line, err := rl.Readline()
		if err == readline.ErrInterrupt {
			if strings.TrimSpace(line) == "" {
				continue
			}
		} else if err != nil {
			return nil
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == "exit" || line == "quit" {
			return nil
		}
		args, err := shlex.Split(line)
		if err != nil {
			fmt.Println("parse error:", err)
			continue
		}
		if len(args) == 1 && args[0] == "help" {
			args = []string{"help"}
		}
		if err := exec(args); err != nil {
			fmt.Println("error:", err)
		}
	}
}

func ReadSecret() (string, error) {
	value, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	return string(value), err
}

func historyFile() string {
	dir, err := os.UserCacheDir()
	if err != nil || strings.TrimSpace(dir) == "" {
		return filepath.Join(os.TempDir(), "mnemox_history")
	}
	dir = filepath.Join(dir, "mnemox")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return filepath.Join(os.TempDir(), "mnemox_history")
	}
	return filepath.Join(dir, "history")
}
