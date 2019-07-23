package jwtis

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/karantin2020/svalkey/testutils"

	"github.com/abronan/valkeyrie/store"
	fuzz "github.com/google/gofuzz"
	"github.com/karantin2020/svalkey"
	"github.com/stretchr/testify/assert"
)

var (
	testSecret = [32]byte{}
)

func newMockStore() store.Store {
	// boltdb.Register()
	// m, err := valkeyrie.NewStore(store.BOLTDB, []string{"./.inner/test.db"},
	// 	&store.Config{
	// 		Bucket:            "testBucket",
	// 		PersistConnection: true,
	// 	})
	// if err != nil {
	// 	panic("error create test boltdb store: " + err.Error())
	// }
	m := testutils.NewMock()
	return m
}

func TestNewKeysRepo(t *testing.T) {
	type args struct {
		repoOpts *KeysRepoOptions
	}
	fs := fuzz.New().NumElements(32, 32)
	fs.Fuzz(&testSecret)
	mockStore := newMockStore()
	store, err := svalkey.NewJSONStore(mockStore, []byte{1, 0}, testSecret)
	if err != nil {
		t.Errorf("NewKeysRepo() error: error create new store: %v", err)
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
				repoOpts: &KeysRepoOptions{
					Store:  store,
					Prefix: "test",
					Opts: &DefaultOptions{
						SigAlg:          "ES256",
						SigBits:         256,
						EncAlg:          "ECDH-ES+A256KW",
						EncBits:         256,
						Expiry:          time.Hour * 4320,
						AuthTTL:         time.Hour * 72,
						RefreshTTL:      time.Hour * 720,
						RefreshStrategy: "noRefresh",
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewKeysRepo(tt.args.repoOpts)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewKeysRepo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			_, err = got.NewKey("testKid", &DefaultOptions{
				RefreshStrategy: "",
			})
			if err != nil {
				t.Errorf("NewKeysRepo() error: error create new key: %s", err.Error())
				return
			}
			testKey, err := got.GetPrivateKeys("testKid")
			if err != nil {
				t.Errorf("NewKeysRepo() error: error get private key: %s", err.Error())
				return
			}
			binKey1, err := json.MarshalIndent(&testKey, "", "  ")
			if err != nil {
				t.Errorf("NewKeysRepo() error: error marshal test key: %s", err.Error())
				return
			}
			var tseKeys SigEncKeys
			err = json.Unmarshal(binKey1, &tseKeys)
			if err != nil {
				t.Errorf("NewKeysRepo() error: error unmarshal test key: %s", err.Error())
				return
			}
			binKey1, err = json.MarshalIndent(&tseKeys, "", "  ")
			if err != nil {
				t.Errorf("NewKeysRepo() error: error re-marshal test key: %s", err.Error())
				return
			}
			// err = got.LoadAll()
			// if err != nil {
			// 	t.Errorf("NewKeysRepo() error: error load all keys: %s", err.Error())
			// 	return
			// }
			// seKeys, err := got.GetPublicKeys("testKid")
			// if err != nil {
			// 	t.Errorf("NewKeysRepo() error: error get test keys: %s", err.Error())
			// 	return
			// }
			seKeys, err := got.GetPrivateKeys("testKid")
			if err != nil {
				t.Errorf("NewKeysRepo() error: error get test keys: %s", err.Error())
				return
			}
			binKey2, err := json.MarshalIndent(&seKeys, "", "  ")
			if err != nil {
				t.Errorf("NewKeysRepo() error: error marshal se key: %s", err.Error())
				return
			}
			if !bytes.Equal(binKey1, binKey2) {
				t.Error("save-load should not lose information")
			}
			assert.Equal(t, tseKeys, seKeys, "NewKeysRepo() error: loaded key is not equal to original key: got = %#v, want %#v", tseKeys, seKeys)

			err = got.DelKey("testKid")
			if err != nil {
				t.Errorf("NewKeysRepo() error: error delete test key: %s", err.Error())
				return
			}
			// _, err = got.ListKeys()
			// if err != nil {
			// 	t.Errorf("NewKeysRepo() error: error get keys list: %s", err.Error())
			// 	return
			// }
		})
	}
}
