package main

import (
	"fmt"
	"os"
	"testing"
)

func TestEnvWithDefaultBool(t *testing.T) {
	tests := []struct {
		envValue     string
		expectedBool bool
	}{
		{"true", true},
		{"TRUE", true},
		{"yes", true},
		{"YES", true},
		{"On", true},
		{"false", false},
		{"FALSE", false},
		{"No", false},
		{"off", false},
		{"False", false},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("Value '%s'", test.envValue), func(t *testing.T) {
			os.Setenv("TEST_VAR", test.envValue)
			actual := envWithDefaultBool("TEST_VAR", false)
			if actual != test.expectedBool {
				t.Errorf("Expected envWithDefaultBool('%s', false) to be %v, but got %v", test.envValue, test.expectedBool, actual)
			}
			actual = envWithDefaultBool("TEST_VAR", true)
			if actual != test.expectedBool {
				t.Errorf("Expected envWithDefaultBool('%s', true) to be %v, but got %v", test.envValue, test.expectedBool, actual)
			}
		})
	}
}
