package cdk_preflight

import rego.v1

# 鍵は base64 の DER（PKCS#8）をそのまま渡す。PEM のまま貼ると armor 行と改行で
# pattern に落ちる——ファイルから読んで渡す書き方で一番踏みやすい間違い。スキーマは
# このプロパティに pattern を持たない。
# 鍵の中身は診断に出さない（秘密鍵が synth の出力に載るのは、ルールが無いより悪い）。
violation contains make_diag_full("pf-ses-dkim-private-key-base64", "ERROR", name,
	"Properties.DkimSigningAttributes.DomainSigningPrivateKey",
	sprintf("DomainSigningPrivateKey (%d characters) is not bare base64; the identity create fails with \"Value at 'dkimSigningAttributes.domainSigningPrivateKey' failed to satisfy constraint: Member must satisfy regular expression pattern: ^[a-zA-Z0-9+/]+={0,2}$\"", [count(k)]),
	"Pass the DER key as one base64 line (openssl rsa -outform DER | base64), without the PEM header, footer or newlines",
	"https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_DkimSigningAttributes.html") if {
	some name in resources_of_type("AWS::SES::EmailIdentity")
	k := object.get(_pf_ses_dkim(name), "DomainSigningPrivateKey", null)
	_pf_ses_lit(k)
	not regex.match(`^[A-Za-z0-9+/]+={0,2}$`, k)
}
