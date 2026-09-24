package cdk_preflight

import rego.v1

# MAIL FROM ドメインは identity の真部分ドメインでなければならない。identity 自身を
# 指す形も拒否される（実測: 同じ文面が返る）。identity がメールアドレスのときは
# 「identity のドメイン」が @ の後ろになり比較の形が変わるので、ドメイン identity だけを見る。
violation contains make_diag_full("pf-ses-mail-from-domain-subdomain-of-identity", "ERROR", name,
	"Properties.MailFromAttributes.MailFromDomain",
	sprintf("MailFromDomain '%v' is not a subdomain of the identity '%v'; the MAIL FROM attributes call fails with \"Provided MAIL-FROM domain <%v> is not subdomain of the domain of the identity <%v>.\"", [mf, ident, mf, ident]),
	sprintf("Use a subdomain of the identity, e.g. mail.%v", [ident]),
	"https://docs.aws.amazon.com/ses/latest/dg/mail-from.html") if {
	some name in resources_of_type("AWS::SES::EmailIdentity")
	ident := resolve(name, "Properties.EmailIdentity")
	_pf_ses_lit(ident)
	not contains(ident, "@")
	mf := resolve(name, "Properties.MailFromAttributes.MailFromDomain")
	_pf_ses_lit(mf)
	not endswith(mf, concat("", [".", ident]))
}
