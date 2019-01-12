// Copy from https://github.com/square/go-jose/jwk-keygen
// Code author is Square Inc.
//
// Licensed under the Apache License, Version 2.0

package jwtis

import (
	"testing"
)

func TestGenerateKeys(t *testing.T) {
	type args struct {
		kid string
		opt KeyOptions
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "test generate sign keys no error",
			args: args{
				kid: "testkid",
				opt: KeyOptions{
					Use:  "sig",
					Alg:  "RS256",
					Bits: 2048,
				},
			},
			wantErr: false,
		},
		{
			name: "test generate enc keys no error",
			args: args{
				kid: "testkid",
				opt: KeyOptions{
					Use:  "enc",
					Alg:  "ECDH-ES+A256KW",
					Bits: 521,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			/* priv */ _, _, err := GenerateKeys(tt.args.kid, tt.args.opt)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateKeys() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			// fmt.Printf("%+v\n", priv)
			// raw, err := priv.MarshalJSON()
			// if err != nil {
			// 	t.Errorf("GenerateKeys() error marshal key: %v", err)
			// 	return
			// }
			// fmt.Printf("%s\n", string(raw))
			// pub := priv.Public()
			// raw, err = pub.MarshalJSON()
			// if err != nil {
			// 	t.Errorf("GenerateKeys() error marshal key: %v", err)
			// 	return
			// }
			// fmt.Printf("%s\n", string(raw))
		})
	}
}
