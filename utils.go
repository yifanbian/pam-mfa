package main

import (
	"bufio"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"os"
)

func ReadLine(r io.Reader) (string, error) {
	return bufio.NewReader(r).ReadString('\n')
}

func ReadPassword(fd int) (string, error) {
	pwd, err := terminal.ReadPassword(fd)
	return string(pwd[:]), err
}

func ReadLineFromStdin() (string, error) {
	return ReadLine(os.Stdin)
}

func ReadPasswordFromStdin() (string, error) {
	return ReadPassword(int(os.Stdin.Fd()))
}
