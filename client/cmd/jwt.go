package cmd

import (
	"encoding/json"
	"fmt"

	cli "github.com/jawher/mow.cli"
	jwts "github.com/karantin2020/jwtis/pkg/services/jwt"
	"go.uber.org/zap"

	pretty "github.com/hokaccha/go-prettyjson"
)

func jwtCmd(cmd *cli.Cmd) {
	cmd.Command("newJWT", "generate new token", newJWTCmd)
	cmd.Command("renewJWT", "renew token", renewJWTCmd)
	cmd.Command("revokeJWT", "revoke token", revokeJWTCmd)
}

func newJWTCmd(cmd *cli.Cmd) {
	var in = &jwts.NewJWTRequest{}
	cmd.StringOptPtr(&in.KID, "kid", "", "Keys ID (kid) value (string, required)")
	var claims string
	cmd.StringOptPtr(&claims, "claims", "{}", "Claims value in json stringified format (string)")
	cmd.Action = func() {
		if in.KID == "" {
			log.Error("error call remote NewJWT", zap.String("error", "kid must not be empty string"))
			cli.Exit(1)
		}
		mapped := map[string]interface{}{}
		err := json.Unmarshal([]byte(claims), &mapped)
		if err != nil {
			log.Error("error marshal claims string option", zap.Error(err))
			cli.Exit(1)
		}
		in.Claims = mapped
		s, _ := pretty.Marshal(in)
		fmt.Println(string(s))
		resp, err := remote.NewJWT(in)
		if err != nil {
			log.Error("error call remote NewJWT", zap.Error(err))
			cli.Exit(1)
		}
		s, _ = pretty.Marshal(resp)
		fmt.Println(string(s))
	}
}

func renewJWTCmd(cmd *cli.Cmd) {
	var in = &jwts.RenewJWTRequest{}
	cmd.StringOptPtr(&in.KID, "kid", "", "Keys ID (kid) value (string, required)")
	cmd.StringOptPtr(&in.RefreshToken, "refresh", "", "Refresh token (string, required)")
	cmd.StringOptPtr(&in.RefreshStrategy, "strategy", "", "Refresh strategy (string)")
	cmd.Action = func() {
		if in.KID == "" {
			log.Error("error call remote RenewJWT", zap.String("error", "kid must not be empty string"))
			cli.Exit(1)
		}
		if in.RefreshToken == "" {
			log.Error("error call remote RenewJWT", zap.String("error", "refresh token must not be empty string"))
			cli.Exit(1)
		}
		resp, err := remote.RenewJWT(in)
		if err != nil {
			log.Error("error call remote NewJWT", zap.Error(err))
			cli.Exit(1)
		}
		s, _ := pretty.Marshal(resp)
		fmt.Println(string(s))
	}
}

func revokeJWTCmd(cmd *cli.Cmd) {
	var in = &jwts.RevokeJWTRequest{}
	cmd.StringOptPtr(&in.KID, "kid", "", "Keys ID (kid) value (string, required)")
	cmd.StringOptPtr(&in.RefreshToken, "refresh", "", "Refresh token (string, required)")
	cmd.StringOptPtr(&in.ID, "id", "", "JWT id to revoke (string, required)")
	cmd.Action = func() {
		if in.KID == "" {
			log.Error("error call remote RevokeJWT", zap.String("error", "kid must not be empty string"))
			cli.Exit(1)
		}
		if in.RefreshToken == "" {
			log.Error("error call remote RevokeJWT", zap.String("error", "refresh token must not be empty string"))
			cli.Exit(1)
		}
		if in.ID == "" {
			log.Error("error call remote RevokeJWT", zap.String("error", "id must not be empty string"))
			cli.Exit(1)
		}
		resp, err := remote.RevokeJWT(in)
		if err != nil {
			log.Error("error call remote NewJWT", zap.Error(err))
			cli.Exit(1)
		}
		s, _ := pretty.Marshal(resp)
		fmt.Println(string(s))
	}
}
