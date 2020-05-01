package cmd

import (
	"fmt"

	"github.com/karantin2020/jwtis/version"
)

// GreetingMsg prints welcome info
func (r *rootCmd) greetingMsg() {
	fmt.Printf("Welcome. Started %s version %s\n", r.name, version.AppVersion)
	if !r.exists {
		fmt.Printf("Generated new password: '%s'\n", string(encodeBytes(r.password[:])))
		fmt.Printf("Please save the password safely, it's not recoverable\n")
	}
}
