package client

import (
	"fmt"
	"reflect"
	"testing"

	pb "github.com/karantin2020/jwtis/api/pb"
	"google.golang.org/grpc"
	"gopkg.in/square/go-jose.v2"
)

var testaddr = "127.0.0.1:40430"

func TestNew(t *testing.T) {
	type args struct {
		id     string
		clOpts Opts
		conn   *grpc.ClientConn
		opts   []grpc.CallOption
	}
	tests := []struct {
		name string
		args args
		want *Client
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(tt.args.id, tt.args.clOpts, tt.args.conn, tt.args.opts...); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClient_Register(t *testing.T) {
	conn, err := grpc.Dial(testaddr, grpc.WithInsecure())
	if err != nil {
		t.Errorf("error starting grpc connection: %v\n", err)
	}
	c := &Client{
		cfg: Config{
			ID: "test1",
		},
		grpcOpts:     []grpc.CallOption{},
		client:       pb.NewJWTISClient(conn),
		PublicSigKey: jose.JSONWebKey{},
		PublicEncKey: jose.JSONWebKey{},
	}
	tests := []struct {
		name    string
		want    *pb.RegisterClientResponse
		wantErr bool
	}{
		{
			"Positive register call",
			nil,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.Register()
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.Register() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			fmt.Printf("received resp: %v\n", got)
			// if !reflect.DeepEqual(got, tt.want) {
			// 	t.Errorf("Client.Register() = %v, want %v", got, tt.want)
			// }
		})
	}
}
