package jwtis

import (
	"fmt"
	"testing"

	jose "gopkg.in/square/go-jose.v2"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

func TestClaimsSigned(t *testing.T) {
	rawSig := `{"use":"sig","kty":"RSA","kid":"testkid","alg":"RS256","n":"wfshHSGBh7PHnq5k6fVIjurIKrAU4mjcjTtErWlrcsmeBTq-f05dPHIDsvIuGAsJUqbslZvIuIamBbYzDX5rKjUOGE7tCf3cmGpaCKdz3c744u7lFNRt_xxS__qasGqGqeKsjzSuzZvvFnJg8j6r8L0U53c3tHQlMDUzj2l3ictLni7ZfOxO0B8sddqU8vE7snYpHSgC7z3am4c9JcGBsC-P844-6SUd75EtdlALXGuGcshPAGTUxoEp3lXUMBlmbUyfWqGjHXCxZlpa4k-GFLx5jGUYdfllIHkHxDawhkrVP5xtCjnt89CTuZ-a-_46JGHJNN1CN88Ejc3IKIpGdw","e":"AQAB","d":"kSPh5vYHAQ5XMjeycguBOs4Y7zfIqI9lVpceD9Js_vo0Lh2CI6byxCNa-S2Tp5G6bAlRw69IRCkbV_K3yETq0i3YWf_UBEHaKICK1SbV3wTZ3JJ6_Vbk5pi-0aEk1RMfp0Vfb9cvY9Bk2BrExvx1ki8n0Pi2yWKN4MAt0ARN2N7hjkiZv2qYipDDxCLJ10aWPjuNlzydxFu60O7eVeme-pVXDcedFOY2zJ3j18GnktAz_I9lcNBgx5zW1y0vzQg9Po4MYUxd2bPKKp27fqWa2-n5WTrZl10IBgtumjW8Fy9T2XKv3D6qyRwvQB1C_i5jiFuAuQqH_R-9N63qJcu1gQ","p":"0O9jjEQLBMM-RWc3SvfFkx48phI-aj1e_PbFgd89TtkEywMX8F-SmjjLZXO_Op7_DVYXM5G_8zyPxTMVp0rA38_aIKCYZ-tDqQVRgbv3wByX96YSdSqpq59M6CPggvmsEFzjyGgmKPKIhxVHPzQ24ftqAKqMt8DmggDebwlBhjE","q":"7a1iPbTRCvU2MiV4WBDtkQo-a5OunmQDKgICfgsluJJbcCkU9T2a49e-HW6lc28YHRQSDgDq1FdQpZ0iRty98Nnn9x5PfBv4GJJGu7lke6PgfHQYBsnN--_fu0baVP3j-qeBfDsXgznWQhQ7RhC8PyuKn9D8O3z8i4h4eYiV5Sc","dp":"Za0p37e5OP8ezb2WHeiIALlFQHg-YYsuL6KTqUkPV9Cq0XTW8IZCHMUozl1OoWOAsWfE8LasF93QBWJ_1iK9y-0ltJ0SrffCvH03FhB4V8hSeBUchGJXoYprbckP2A1Sm7_opb1xXJnysPI88tghIUYtZteYlU_NnVR46sYxWfE","dq":"VH8WdP-Kbc3dVZiSnyRtgOnWZSJcqvy9Tzrlre_CmkqV7Vr9k24yWZwCf64tbctqFDRlcssKsTDVf_tMC0tAz5Z4bBc_hMzgt8ORF_4B5h7NmREg1ZD7BP0zWf4Hcr3MRfk1BHhxlHqEXHua0v7yHbcaElUWxwNZOTXsNrDDMXM","qi":"NDYIa8D5V8nfsgjSyC7Ega4uoCPXFus5jFWND7dsb6FaijGXgpEIw6o10bfIsQ1-ajPLGPvF4y_Iz53LRpdcWdD01VdwAlBOsRIrQkKoyXt8cp_1pZe7eP5RVlpnwYU97CJD3GPqbWhKcZmjDiLb4t3zNOvqGKZLwlamg35Yksk"}`
	rawJWT := `eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJTY29wZXMiOlsic3RyZWFtOnJlYWQiLCJzdHJlYW06d3JpdGUiXSwiaXNzIjoidGVzdF9pc3N1ZXIiLCJzdWIiOiJ0ZXN0X3N1YmplY3QifQ.KzjTq8NSwZqmHWj0Po94qdxg9wKCJoZ1HB4KHkxcmAJI8nJJ4K9Mfmrgu-YPAdI2VXWm9ga19DmQQ5sDZDlUKpt4nREay9D35R7M6s0cDq5GIUoY9WRujZshsWkMvempkrf96XbzHXhKXg8ezarDL1B4AN_6579e2O03kS2-x3l56Y20IkSzMw5qtQiieDpaZH8A766A2TgrZNXVDsedRv5VcXY-qmbqr-IaPsZWHr1Xg9B5rQYcufM1pPPWYrjowKUk3oEz0Ja9E1aSuqI7Lfi34T2rZL51qfZDtnkWTKY-S9q5NarKaXP3cdePK3GCOIs_5-uz0Mqddw9Lnyr4tQ`
	var privSig jose.JSONWebKey
	err := privSig.UnmarshalJSON([]byte(rawSig))
	if err != nil {
		t.Errorf("ClaimsSigned() error = %v", err)
		return
	}
	type args struct {
		sigkey *jose.JSONWebKey
		raw    string
		dest   []interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "test parse signed",
			args: args{
				sigkey: &privSig,
				raw:    rawJWT,
				dest: []interface{}{
					&jwt.Claims{},
					&struct {
						Scopes []string
					}{},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ClaimsSigned(tt.args.sigkey, tt.args.raw, tt.args.dest...); (err != nil) != tt.wantErr {
				t.Errorf("ClaimsSigned() error = %v, wantErr %v", err, tt.wantErr)
			}
			// fmt.Printf("claims: %+v\noptClaims: %+v\n", tt.args.dest[0], tt.args.dest[1])
		})
	}
}

func TestJWTSigned(t *testing.T) {
	rawSig := `{"use":"sig","kty":"RSA","kid":"testkid","alg":"RS256","n":"wfshHSGBh7PHnq5k6fVIjurIKrAU4mjcjTtErWlrcsmeBTq-f05dPHIDsvIuGAsJUqbslZvIuIamBbYzDX5rKjUOGE7tCf3cmGpaCKdz3c744u7lFNRt_xxS__qasGqGqeKsjzSuzZvvFnJg8j6r8L0U53c3tHQlMDUzj2l3ictLni7ZfOxO0B8sddqU8vE7snYpHSgC7z3am4c9JcGBsC-P844-6SUd75EtdlALXGuGcshPAGTUxoEp3lXUMBlmbUyfWqGjHXCxZlpa4k-GFLx5jGUYdfllIHkHxDawhkrVP5xtCjnt89CTuZ-a-_46JGHJNN1CN88Ejc3IKIpGdw","e":"AQAB","d":"kSPh5vYHAQ5XMjeycguBOs4Y7zfIqI9lVpceD9Js_vo0Lh2CI6byxCNa-S2Tp5G6bAlRw69IRCkbV_K3yETq0i3YWf_UBEHaKICK1SbV3wTZ3JJ6_Vbk5pi-0aEk1RMfp0Vfb9cvY9Bk2BrExvx1ki8n0Pi2yWKN4MAt0ARN2N7hjkiZv2qYipDDxCLJ10aWPjuNlzydxFu60O7eVeme-pVXDcedFOY2zJ3j18GnktAz_I9lcNBgx5zW1y0vzQg9Po4MYUxd2bPKKp27fqWa2-n5WTrZl10IBgtumjW8Fy9T2XKv3D6qyRwvQB1C_i5jiFuAuQqH_R-9N63qJcu1gQ","p":"0O9jjEQLBMM-RWc3SvfFkx48phI-aj1e_PbFgd89TtkEywMX8F-SmjjLZXO_Op7_DVYXM5G_8zyPxTMVp0rA38_aIKCYZ-tDqQVRgbv3wByX96YSdSqpq59M6CPggvmsEFzjyGgmKPKIhxVHPzQ24ftqAKqMt8DmggDebwlBhjE","q":"7a1iPbTRCvU2MiV4WBDtkQo-a5OunmQDKgICfgsluJJbcCkU9T2a49e-HW6lc28YHRQSDgDq1FdQpZ0iRty98Nnn9x5PfBv4GJJGu7lke6PgfHQYBsnN--_fu0baVP3j-qeBfDsXgznWQhQ7RhC8PyuKn9D8O3z8i4h4eYiV5Sc","dp":"Za0p37e5OP8ezb2WHeiIALlFQHg-YYsuL6KTqUkPV9Cq0XTW8IZCHMUozl1OoWOAsWfE8LasF93QBWJ_1iK9y-0ltJ0SrffCvH03FhB4V8hSeBUchGJXoYprbckP2A1Sm7_opb1xXJnysPI88tghIUYtZteYlU_NnVR46sYxWfE","dq":"VH8WdP-Kbc3dVZiSnyRtgOnWZSJcqvy9Tzrlre_CmkqV7Vr9k24yWZwCf64tbctqFDRlcssKsTDVf_tMC0tAz5Z4bBc_hMzgt8ORF_4B5h7NmREg1ZD7BP0zWf4Hcr3MRfk1BHhxlHqEXHua0v7yHbcaElUWxwNZOTXsNrDDMXM","qi":"NDYIa8D5V8nfsgjSyC7Ega4uoCPXFus5jFWND7dsb6FaijGXgpEIw6o10bfIsQ1-ajPLGPvF4y_Iz53LRpdcWdD01VdwAlBOsRIrQkKoyXt8cp_1pZe7eP5RVlpnwYU97CJD3GPqbWhKcZmjDiLb4t3zNOvqGKZLwlamg35Yksk"}`
	rawJWT := `eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJTY29wZXMiOlsic3RyZWFtOnJlYWQiLCJzdHJlYW06d3JpdGUiXSwiaXNzIjoidGVzdF9pc3N1ZXIiLCJzdWIiOiJ0ZXN0X3N1YmplY3QifQ.KzjTq8NSwZqmHWj0Po94qdxg9wKCJoZ1HB4KHkxcmAJI8nJJ4K9Mfmrgu-YPAdI2VXWm9ga19DmQQ5sDZDlUKpt4nREay9D35R7M6s0cDq5GIUoY9WRujZshsWkMvempkrf96XbzHXhKXg8ezarDL1B4AN_6579e2O03kS2-x3l56Y20IkSzMw5qtQiieDpaZH8A766A2TgrZNXVDsedRv5VcXY-qmbqr-IaPsZWHr1Xg9B5rQYcufM1pPPWYrjowKUk3oEz0Ja9E1aSuqI7Lfi34T2rZL51qfZDtnkWTKY-S9q5NarKaXP3cdePK3GCOIs_5-uz0Mqddw9Lnyr4tQ`
	var priv jose.JSONWebKey
	err := priv.UnmarshalJSON([]byte(rawSig))
	if err != nil {
		t.Errorf("ClaimsSigned() error = %v", err)
		return
	}
	type args struct {
		sigkey *jose.JSONWebKey
		claims []interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "test sign jwt",
			args: args{
				sigkey: &priv,
				claims: []interface{}{
					jwt.Claims{
						Subject: "test_subject",
						Issuer:  "test_issuer",
					},
					struct {
						Scopes []string
					}{
						Scopes: []string{
							"stream:read",
							"stream:write",
						},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := JWTSigned(tt.args.sigkey, tt.args.claims...)
			if (err != nil) != tt.wantErr {
				t.Errorf("JWTSigned() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != rawJWT {
				t.Errorf("JWTSigned(): result jwt is not equal to test result")
				return
			}
		})
	}
}

func TestJWTSignedAndEncrypted(t *testing.T) {
	// KeyOptions{
	// 	Use:  "enc",
	// 	Alg:  "RSA-OAEP-256",
	// 	Bits: 2048}
	privEncRaw := `{"use":"enc","kty":"RSA","kid":"testEnc","alg":"RSA-OAEP-256","n":"yHBLyZinsk-LRTSstYNzmLBJbAa8RQmrJuEQfCNCPzRKqe_jeFiAlOjS-DYBpXVS6VkFHXqNpukS64__nzEvV1XNdYgaWqcP7Kvo6dfaXUdBAcDOIbBt6XHZQq4GKMed3OTf_oqSLNU0Q2kuxBpUof_jJVsThIDdFGEBd5o_3OI7wOB8Hb-QPwimgwQRekwvqvCX79paEM1FY0YiZnCIqW32JjHGL33hDeoOIE2pABTbnRZ-r8_spROQbk98hujKAYgaYI9X66PpHzPgXUXtwmKUYM2EVcnFFvOF7rcA3GduCPcKqjA2v7VYic3zYtgbnsCNP0lWHIW7ghVCaY1Q7Q","e":"AQAB","d":"rkbtrpib3u9IweC99okYPn-xJ0tn8YMpnIF-iuFBXaFC9iVNnDsfedpCbWzP26R6dchgKTSA68qmF8m50hm69u302id_-qhdsUP8HS8Af7BPto2E7UfxGVRTOqYDVvvRp9odZL3pwS-T5LUU44-dXMoYH0fkXYaKM4jw9KRauNs195ZCnS9rU66kfTvZuFLOra9uF7EvIyudZpv1shLA1bJO5vFKLeL86z336n2HDqkbqOA7THyA7_CL7pB3qIsvjpcqHDHQNi6GPvuJHbK1dUZd5Qsv8eZvFFplM72T2q_cQjM6jKCE6njnta_vqEwiqsr865LfMT-dEXH_EJnHZQ","p":"1zK-fL2PrTa28nnmBgLBAtLksw1Wv_XPM_kkoUXbdgK8XPzUpEopX0rE8PqMU2b05npdAX6W0KqsRlTkeIdCdh0h1_nexFXM8NCSYGmom6YlHtujflmdvaIS1NBw-H3MED3f_S2mSiEUnZlPjlNVH57Iw8M6dprHVVGjNLIt1Ns","q":"7nEnm53DFWJ-fk8-rK1wSYJAW_pOMxgAY1umU2gAzhewrwDZVVkxU5K6pM63_MQIWQFofeKplVRTFRvkQpIxiLHAYbMBXng-bo7pWDIiRxArWUhUddFyKszwWt6MJ45HYMj8PyS7MR0FxriElqYEorOQeiy-JIaNOgJR7e7lt9c","dp":"OKb2ONaajWobDYiDws9Uyo6EgJKhZNWsX61WNFK0rMOZnQ0-WaXgcGK5qAr9iDNRg59w_qS5xWM5CSbuIsDRAVE4CKiSObOwyTDPaCxIo_lASnhd-TRUb4jMVlQteW18nEX9wqQS4-8Dg13J8NkFTta5Wbf6myCyG0brpULHCAM","dq":"ib-7Nw6UFjWZiBT1y0JDXWQvFDPtm1zhVIUs-IBb_rP28ZMW-1SUx4g75Vw7NH53qBvFJvycJdXaTZaYbtEQZrzxvD9yqgXjY3GSYs5LuSwhLuo3SP1f7FQLAyQQagWrPMG_4CazMfNnU99jUbjFcs0zyTEyA93rlriiZkeeVG8","qi":"A3aAvpXLrw2q4d2P4u4Jbyi3sKJXUP85l7J_L6ExarD22dtqKJMGbSg023-SJzRKNV85_7VAWxgOKITcmLNfRCWHFH6-9rR49OdIJ8eHgML0iwnwdUwHeW0NbSNs2BJh-_BEbdcR9dg1KDt0P2Gp0vRFp2DEAGErB_9n3dOmGlU"}`
	rawSig := `{"use":"sig","kty":"RSA","kid":"testkid","alg":"RS256","n":"wfshHSGBh7PHnq5k6fVIjurIKrAU4mjcjTtErWlrcsmeBTq-f05dPHIDsvIuGAsJUqbslZvIuIamBbYzDX5rKjUOGE7tCf3cmGpaCKdz3c744u7lFNRt_xxS__qasGqGqeKsjzSuzZvvFnJg8j6r8L0U53c3tHQlMDUzj2l3ictLni7ZfOxO0B8sddqU8vE7snYpHSgC7z3am4c9JcGBsC-P844-6SUd75EtdlALXGuGcshPAGTUxoEp3lXUMBlmbUyfWqGjHXCxZlpa4k-GFLx5jGUYdfllIHkHxDawhkrVP5xtCjnt89CTuZ-a-_46JGHJNN1CN88Ejc3IKIpGdw","e":"AQAB","d":"kSPh5vYHAQ5XMjeycguBOs4Y7zfIqI9lVpceD9Js_vo0Lh2CI6byxCNa-S2Tp5G6bAlRw69IRCkbV_K3yETq0i3YWf_UBEHaKICK1SbV3wTZ3JJ6_Vbk5pi-0aEk1RMfp0Vfb9cvY9Bk2BrExvx1ki8n0Pi2yWKN4MAt0ARN2N7hjkiZv2qYipDDxCLJ10aWPjuNlzydxFu60O7eVeme-pVXDcedFOY2zJ3j18GnktAz_I9lcNBgx5zW1y0vzQg9Po4MYUxd2bPKKp27fqWa2-n5WTrZl10IBgtumjW8Fy9T2XKv3D6qyRwvQB1C_i5jiFuAuQqH_R-9N63qJcu1gQ","p":"0O9jjEQLBMM-RWc3SvfFkx48phI-aj1e_PbFgd89TtkEywMX8F-SmjjLZXO_Op7_DVYXM5G_8zyPxTMVp0rA38_aIKCYZ-tDqQVRgbv3wByX96YSdSqpq59M6CPggvmsEFzjyGgmKPKIhxVHPzQ24ftqAKqMt8DmggDebwlBhjE","q":"7a1iPbTRCvU2MiV4WBDtkQo-a5OunmQDKgICfgsluJJbcCkU9T2a49e-HW6lc28YHRQSDgDq1FdQpZ0iRty98Nnn9x5PfBv4GJJGu7lke6PgfHQYBsnN--_fu0baVP3j-qeBfDsXgznWQhQ7RhC8PyuKn9D8O3z8i4h4eYiV5Sc","dp":"Za0p37e5OP8ezb2WHeiIALlFQHg-YYsuL6KTqUkPV9Cq0XTW8IZCHMUozl1OoWOAsWfE8LasF93QBWJ_1iK9y-0ltJ0SrffCvH03FhB4V8hSeBUchGJXoYprbckP2A1Sm7_opb1xXJnysPI88tghIUYtZteYlU_NnVR46sYxWfE","dq":"VH8WdP-Kbc3dVZiSnyRtgOnWZSJcqvy9Tzrlre_CmkqV7Vr9k24yWZwCf64tbctqFDRlcssKsTDVf_tMC0tAz5Z4bBc_hMzgt8ORF_4B5h7NmREg1ZD7BP0zWf4Hcr3MRfk1BHhxlHqEXHua0v7yHbcaElUWxwNZOTXsNrDDMXM","qi":"NDYIa8D5V8nfsgjSyC7Ega4uoCPXFus5jFWND7dsb6FaijGXgpEIw6o10bfIsQ1-ajPLGPvF4y_Iz53LRpdcWdD01VdwAlBOsRIrQkKoyXt8cp_1pZe7eP5RVlpnwYU97CJD3GPqbWhKcZmjDiLb4t3zNOvqGKZLwlamg35Yksk"}`
	// pubEncRaw := '{"use":"enc","kty":"RSA","kid":"testEnc","alg":"RSA-OAEP-256","n":"yHBLyZinsk-LRTSstYNzmLBJbAa8RQmrJuEQfCNCPzRKqe_jeFiAlOjS-DYBpXVS6VkFHXqNpukS64__nzEvV1XNdYgaWqcP7Kvo6dfaXUdBAcDOIbBt6XHZQq4GKMed3OTf_oqSLNU0Q2kuxBpUof_jJVsThIDdFGEBd5o_3OI7wOB8Hb-QPwimgwQRekwvqvCX79paEM1FY0YiZnCIqW32JjHGL33hDeoOIE2pABTbnRZ-r8_spROQbk98hujKAYgaYI9X66PpHzPgXUXtwmKUYM2EVcnFFvOF7rcA3GduCPcKqjA2v7VYic3zYtgbnsCNP0lWHIW7ghVCaY1Q7Q","e":"AQAB"}'
	var privEnc jose.JSONWebKey
	err := privEnc.UnmarshalJSON([]byte(privEncRaw))
	if err != nil {
		t.Errorf("TestJWTSignedAndEncrypted() error = %#v", err)
		return
	}
	fmt.Printf("privEnc: '%#v'\n", privEnc)
	var privSig jose.JSONWebKey
	err = privSig.UnmarshalJSON([]byte(rawSig))
	if err != nil {
		t.Errorf("TestJWTSignedAndEncrypted() error = %v", err)
		return
	}
	fmt.Printf("privSig: '%#v'\n", privSig)
	privEnc = privEnc.Public()
	fmt.Printf("privEnc: '%#v'\n", privEnc)
	// privSig = privSig.Public()
	// fmt.Printf("privSig: '%#v'\n", privSig)
	type args struct {
		enckey *jose.JSONWebKey
		sigkey *jose.JSONWebKey
		claims []interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "test sign jwt",
			args: args{
				enckey: &privEnc,
				sigkey: &privSig,
				claims: []interface{}{
					jwt.Claims{
						Subject: "test_subject",
						Issuer:  "test_issuer",
					},
					struct {
						Scopes []string
					}{
						Scopes: []string{
							"stream:read",
							"stream:write",
						},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := JWTSignedAndEncrypted(tt.args.enckey, tt.args.sigkey, tt.args.claims...)
			if (err != nil) != tt.wantErr {
				t.Errorf("JWTSignedAndEncrypted() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			fmt.Printf("JWT: '%s'\n", got)
			// if got != tt.want {
			// 	t.Errorf("JWTSignedAndEncrypted() = %v, want %v", got, tt.want)
			// }
		})
	}
}
