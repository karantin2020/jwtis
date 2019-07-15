package cmd

import "fmt"

// GreetingMsg prints welcome info
func (r *rootCmd) greetingMsg() {
	fmt.Printf("Welcome. Started %s version %s\n", r.name, r.version)
	if !r.exists {
		fmt.Printf("Generated new password: '%s'\n", string(hexEncode(r.password[:])))
		fmt.Printf("Please save the password safely, it's not recoverable\n")
	}
}
