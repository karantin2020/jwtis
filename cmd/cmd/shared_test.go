package cmd

import (
	"reflect"
	"testing"
)

func Test_newPassword(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "Positive test",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newPassword()
			if (err != nil) != tt.wantErr {
				t.Errorf("newPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_hexEncode(t *testing.T) {
	type args struct {
		src []byte
	}
	pswd, err := newPassword()
	if err != nil {
		t.Errorf("newPassword() error = %v", err)
		return
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Positive test",
			args: args{
				src: pswd[:],
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := hexEncode(tt.args.src)
			decoded, err := hexDecode(encoded)
			if (err != nil) && !tt.wantErr {
				t.Errorf("hexEncode() -> hexDecode() = %v, want %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.src, decoded) {
				t.Errorf("hexEncode() -> hexDecode() non equal: %v != %v", tt.args.src, decoded)
			}
		})
	}
}
