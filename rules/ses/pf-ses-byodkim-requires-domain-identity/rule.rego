package cdk_preflight

import rego.v1

# 持ち込み鍵で署名するのはドメイン単位の DKIM なので、メールアドレスの identity には
# 付けられない。Easy DKIM 側（NextSigningKeyLength だけ）はメールアドレスでも受理される
# ので（実測 2026-09-24）、ルールは BYODKIM の 2 プロパティだけを見る。
violation contains make_diag_full("pf-ses-byodkim-requires-domain-identity", "ERROR", name,
	"Properties.DkimSigningAttributes",
	sprintf("EmailIdentity '%v' is an email address, so it cannot carry BYODKIM signing attributes; the identity create fails with \"For BYODKIM, the EmailIdentity value must be a domain.\"", [ident]),
	"Create the identity for the domain and configure BYODKIM there, or drop DomainSigningSelector/DomainSigningPrivateKey",
	"https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_CreateEmailIdentity.html") if {
	some name in resources_of_type("AWS::SES::EmailIdentity")
	ident := resolve(name, "Properties.EmailIdentity")
	_pf_ses_lit(ident)
	contains(ident, "@")
	_pf_ses_byodkim(name)
}
