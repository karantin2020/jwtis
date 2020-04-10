package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewConfig(t *testing.T) {
	type args struct {
		bucketName string
	}
	tests := []struct {
		name string
		args args
		want func(assert.TestingT, interface{}, ...interface{}) bool
	}{
		{
			name: "Successful test",
			args: args{
				bucketName: "bucketName",
			},
			want: assert.NotNil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewConfig(tt.args.bucketName)
			tt.want(t, got, "New Config pointer must not be nil")
		})
	}
}
