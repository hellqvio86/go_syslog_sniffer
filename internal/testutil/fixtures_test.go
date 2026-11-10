package testutil

import (
	"path/filepath"
	"testing"
)

func TestGenerateFixtures(t *testing.T) {
	targetDir := filepath.Join("..", "..", "testdata")
	if err := GenerateTestFixtures(targetDir); err != nil {
		t.Fatalf("failed to generate fixtures: %v", err)
	}
}
