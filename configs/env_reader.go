package configs

import (
	"bufio"
	"os"
)

// Package configs holds whole logic associated with db,cache and env config

type EnvReader struct{}

func readEnvFile(pathToEnvFile string, amountOfEnvVariables int) (map[string]string, error) {
	file, err := os.OpenFile(pathToEnvFile, os.O_RDONLY, 0o644)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	envVariables := make(map[string]string, amountOfEnvVariables)
	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
	}
	return envVariables, nil
}
