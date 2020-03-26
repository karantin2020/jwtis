package cmd

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"runtime"
)

var (
	// These variables are set using -ldflags
	appVersion     string
	gitBranch      string
	lastCommitSHA  string
	lastCommitTime string
)

// BuildDetails returns a string containing details about the JWTIS binary.
func BuildDetails() string {
	licenseInfo := `Licensed under the MIT License`
	return fmt.Sprintf(`
JWTIS version   : %v
JWTIS SHA-256   : %x
Commit SHA-1     : %v
Commit timestamp : %v
Branch           : %v
Go version       : %v
%s.
Copyright 2018-2020 @karantin2020.
`,
		appVersion, ExecutableChecksum(), lastCommitSHA, lastCommitTime, gitBranch,
		runtime.Version(), licenseInfo)
}

// Version returns a string containing the appVersion.
func Version() string {
	return appVersion
}

// ExecutableChecksum returns a byte slice containing the SHA256 checksum of the executable.
// It returns a nil slice if there's an error trying to calculate the checksum.
func ExecutableChecksum() []byte {
	execPath, err := os.Executable()
	if err != nil {
		return nil
	}
	execFile, err := os.Open(execPath)
	if err != nil {
		return nil
	}
	defer execFile.Close()

	h := sha256.New()
	if _, err := io.Copy(h, execFile); err != nil {
		return nil
	}

	return h.Sum(nil)
}
