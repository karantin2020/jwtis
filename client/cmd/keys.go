package cmd

import (
	"fmt"
	"time"

	cli "github.com/jawher/mow.cli"
	keys "github.com/karantin2020/jwtis/pkg/services/keys"
	"go.uber.org/zap"

	pretty "github.com/hokaccha/go-prettyjson"
)

func keysCmd(cmd *cli.Cmd) {
	cmd.Command("auth", "auth client", authCmd)
	cmd.Command("register", "register new client", registerCmd)
	cmd.Command("update", "update client keys", updateKeysCmd)
	cmd.Command("list", "list all registered clients with keys", listKeysCmd)
	cmd.Command("del", "delete client", delKeysCmd)
	cmd.Command("pubKeys", "show client public keys", publicKeysCmd)
}

func authCmd(cmd *cli.Cmd) {
	var in = &keys.AuthRequest{}
	cmd.StringOptPtr(&in.KID, "kid", "", "Keys ID (kid) value (required)")
	cmd.Action = func() {
		if in.KID == "" {
			log.Error("error call remote Auth", zap.String("error", "kid must not be empty string"))
			cli.Exit(1)
		}
		resp, err := remote.Auth(in)
		if err != nil {
			log.Error("error call remote Auth", zap.Error(err))
		}
		s, _ := pretty.Marshal(resp)
		fmt.Println(string(s))
	}
}

func registerCmd(cmd *cli.Cmd) {
	var in = &keys.RegisterRequest{}
	var (
		expiry     string
		authTTL    string
		refreshTTL string
		err        error
	)
	cmd.StringOptPtr(&in.KID, "kid", "", "Keys ID (kid) value (required)")
	cmd.StringOptPtr(&in.SigAlg, "sigAlg", "", "signature algorithm")
	cmd.StringOptPtr(&in.EncAlg, "encAlg", "", "encode algorithm")
	cmd.IntOptPtr(&in.SigBits, "sigBits", 0, "signature bits")
	cmd.IntOptPtr(&in.EncBits, "encBits", 0, "encode bits")
	cmd.StringOptPtr(&expiry, "Expiry", "", "Expiry")
	cmd.StringOptPtr(&authTTL, "AuthTTL", "", "AuthTTL")
	cmd.StringOptPtr(&refreshTTL, "RefreshTTL", "", "RefreshTTL")
	cmd.StringOptPtr(&in.RefreshStrategy, "RefreshStrategy", "", "RefreshStrategy")
	cmd.Action = func() {
		if expiry != "" {
			in.Expiry, err = time.ParseDuration(expiry)
			if err != nil {
				log.Error("error parse register flags", zap.String("error", err.Error()))
				cli.Exit(1)
			}
		}
		if authTTL != "" {
			in.AuthTTL, err = time.ParseDuration(authTTL)
			if err != nil {
				log.Error("error parse register flags", zap.String("error", err.Error()))
				cli.Exit(1)
			}
		}
		if refreshTTL != "" {
			in.RefreshTTL, err = time.ParseDuration(refreshTTL)
			if err != nil {
				log.Error("error parse register flags", zap.String("error", err.Error()))
				cli.Exit(1)
			}
		}
		if in.KID == "" {
			log.Error("error call remote Register", zap.String("error", "kid must not be empty string"))
			cli.Exit(1)
		}
		resp, err := remote.Register(in)
		if err != nil {
			log.Error("error call remote Register", zap.Error(err))
		}
		s, _ := pretty.Marshal(resp)
		fmt.Println(string(s))
	}
}

func updateKeysCmd(cmd *cli.Cmd) {
	var in = &keys.UpdateKeysRequest{}
	var (
		expiry     string
		authTTL    string
		refreshTTL string
		err        error
	)
	cmd.StringOptPtr(&in.KID, "kid", "", "Keys ID (kid) value (required)")
	cmd.StringOptPtr(&in.SigAlg, "sigAlg", "", "signature algorithm")
	cmd.StringOptPtr(&in.EncAlg, "encAlg", "", "encode algorithm")
	cmd.IntOptPtr(&in.SigBits, "sigBits", 0, "signature bits")
	cmd.IntOptPtr(&in.EncBits, "encBits", 0, "encode bits")
	cmd.StringOptPtr(&expiry, "Expiry", "", "Expiry")
	cmd.StringOptPtr(&authTTL, "AuthTTL", "", "AuthTTL")
	cmd.StringOptPtr(&refreshTTL, "RefreshTTL", "", "RefreshTTL")
	cmd.StringOptPtr(&in.RefreshStrategy, "RefreshStrategy", "", "RefreshStrategy")
	cmd.Action = func() {
		if expiry != "" {
			in.Expiry, err = time.ParseDuration(expiry)
			if err != nil {
				log.Error("error parse register flags", zap.String("error", err.Error()))
				cli.Exit(1)
			}
		}
		if authTTL != "" {
			in.AuthTTL, err = time.ParseDuration(authTTL)
			if err != nil {
				log.Error("error parse register flags", zap.String("error", err.Error()))
				cli.Exit(1)
			}
		}
		if refreshTTL != "" {
			in.RefreshTTL, err = time.ParseDuration(refreshTTL)
			if err != nil {
				log.Error("error parse register flags", zap.String("error", err.Error()))
				cli.Exit(1)
			}
		}
		if in.KID == "" {
			log.Error("error call remote UpdateKeys", zap.String("error", "kid must not be empty string"))
			cli.Exit(1)
		}
		resp, err := remote.UpdateKeys(in)
		if err != nil {
			log.Error("error call remote UpdateKeys", zap.Error(err))
		}
		s, _ := pretty.Marshal(resp)
		fmt.Println(string(s))
	}
}

func listKeysCmd(cmd *cli.Cmd) {
	cmd.Action = func() {
		var in = &keys.ListKeysRequest{}
		resp, err := remote.ListKeys(in)
		if err != nil {
			log.Error("error call remote ListKeys", zap.Error(err))
		}
		s, _ := pretty.Marshal(resp)
		fmt.Println(string(s))
	}
}

func delKeysCmd(cmd *cli.Cmd) {
	var in = &keys.DelKeysRequest{}
	cmd.StringOptPtr(&in.KID, "kid", "", "Keys ID (kid) value (required)")
	cmd.Action = func() {
		if in.KID == "" {
			log.Error("error call remote DelKeys", zap.String("error", "kid must not be empty string"))
			cli.Exit(1)
		}
		_, err := remote.DelKeys(in)
		if err != nil {
			log.Error("error call remote DelKeys", zap.Error(err))
		}
		fmt.Printf("Keys with kid %s are deleted\n", in.KID)
	}
}

func publicKeysCmd(cmd *cli.Cmd) {
	var in = &keys.PublicKeysRequest{}
	cmd.StringOptPtr(&in.KID, "kid", "", "Keys ID (kid) value (required)")
	cmd.Action = func() {
		if in.KID == "" {
			log.Error("error call remote PublicKeys", zap.String("error", "kid must not be empty string"))
			cli.Exit(1)
		}
		resp, err := remote.PublicKeys(in)
		if err != nil {
			log.Error("error call remote PublicKeys", zap.Error(err))
		}
		s, _ := pretty.Marshal(resp)
		fmt.Println(string(s))
	}
}
