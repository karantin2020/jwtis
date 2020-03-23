package grpc

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	grpc1 "github.com/go-kit/kit/transport/grpc"
	service "github.com/karantin2020/jwtis/pkg/service"
	grpc "google.golang.org/grpc"
)

var testaddr = "127.0.0.1:40430"

func TestNew(t *testing.T) {
	type args struct {
		conn    *grpc.ClientConn
		options map[string][]grpc1.ClientOption
	}
	conn, err := grpc.Dial(testaddr, grpc.WithInsecure())
	if err != nil {
		t.Errorf("error starting grpc connection: %v\n", err)
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "test connection",
			args: args{
				conn:    conn,
				options: nil,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.conn, tt.args.options)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			dd := time.Now().AddDate(0, 8, 0)
			dur := time.Until(dd)
			keys, err := got.Register(context.Background(), "testkid6", &service.KeysOptions{
				Expiry: dur,
			})
			if err != nil {
				t.Errorf("Register error: %v", err)
			}
			fmt.Printf("%+v\n", err)
			json, err := json.MarshalIndent(keys, "", "  ")
			if err != nil {
				t.Errorf("MarshalIndent error: %v", err)
			}

			fmt.Println(string(json))
		})
	}
}

var (
	options = map[string][]grpc1.ClientOption{
		"NewJWT":     []grpc1.ClientOption{},
		"RenewJWT":   []grpc1.ClientOption{},
		"RevokeJWT":  []grpc1.ClientOption{},
		"Auth":       []grpc1.ClientOption{},
		"Register":   []grpc1.ClientOption{},
		"UpdateKeys": []grpc1.ClientOption{},
		"ListKeys":   []grpc1.ClientOption{},
		"DelKeys":    []grpc1.ClientOption{},
		"PublicKeys": []grpc1.ClientOption{},
	}
)
