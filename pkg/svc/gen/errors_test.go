package gen_test

import (
	"testing"

	. "github.com/karantin2020/jwtis/pkg/svc/gen"
	errors "github.com/pkg/errors"
	"google.golang.org/grpc/codes"
)

func TestIs(t *testing.T) {
	type args struct {
		err    error
		target error
	}
	err1 := Error(codes.Internal, "test error")
	err2 := Error(codes.Internal, "test error")
	errStd1 := errors.New("test error")
	errStd2 := errors.New("test error")
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "compare self error",
			args: args{
				err:    err1,
				target: err1,
			},
			want: true,
		},
		{
			name: "compare by code and message if status error",
			args: args{
				err:    err1,
				target: err2,
			},
			want: true,
		},
		{
			name: "compare by code and message if std error",
			args: args{
				err:    errStd1,
				target: errStd2,
			},
			want: false,
		},
		{
			name: "compare wrapped by code and message if status error",
			args: args{
				err:    err1,
				target: WrapErr(err1, codes.Unavailable, "wrapper message"),
			},
			want: true,
		},
		{
			name: "compare wrapped by code and message if std error",
			args: args{
				err:    errStd1,
				target: errors.Wrap(errStd1, "wrapper message"),
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Is(tt.args.err, tt.args.target); got != tt.want {
				t.Errorf("Is() = %v, want %v", got, tt.want)
			}
		})
	}
}
