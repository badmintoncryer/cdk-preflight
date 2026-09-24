package cdk_preflight

import rego.v1

# NextSigningKeyLength は Easy DKIM（SES が鍵を作る）側の設定で、持ち込み鍵とは
# 排他。ドキュメントは `[Easy DKIM]` という印だけで、スキーマは 3 つを同時に受ける。
violation contains make_diag_full("pf-ses-dkim-next-signing-key-length-easy-dkim-only", "ERROR", name,
	"Properties.DkimSigningAttributes.NextSigningKeyLength",
	sprintf("NextSigningKeyLength is set together with %v; the identity create fails with \"You cannot configure the identity to use Easy DKIM and Bring Your Own DKIM properties at the same time.\"", [k]),
	"Drop NextSigningKeyLength for BYODKIM, or drop the selector and private key to use Easy DKIM",
	"https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_DkimSigningAttributes.html") if {
	some name in resources_of_type("AWS::SES::EmailIdentity")
	_pf_ses_dkim_set(name, "NextSigningKeyLength")
	some k in _pf_ses_byodkim_keys
	_pf_ses_dkim_set(name, k)
}
