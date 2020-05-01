package version

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"runtime"
)

var (
	/// These variables are set using -ldflags

	// AppVersion variable for version description
	AppVersion string
	// GitBranch variable for version description
	GitBranch string
	// LastCommitSHA variable for version description
	LastCommitSHA string
	// LastCommitTime variable for version description
	LastCommitTime string
	// BuildTime variable for version description
	BuildTime string
)

// BuildDetails returns a string containing details about the JWTIS binary.
func BuildDetails() string {
	licenseInfo := `Licensed under the MIT License`
	return fmt.Sprintf(`
JWTIS version    : %v
JWTIS SHA-256    : %x
Commit SHA-1     : %v
Commit timestamp : %v
Branch           : %v
Go version       : %v
Build time       : %v
%s.
Copyright 2018-2020 @karantin2020.
`,
		AppVersion, ExecutableChecksum(), LastCommitSHA, LastCommitTime, GitBranch,
		runtime.Version(), BuildTime, licenseInfo)
}

// Version returns a string containing the appVersion.
func Version() string {
	return AppVersion
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
