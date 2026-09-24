package cdk_preflight

import rego.v1

# selector は DNS ラベル 1 つになるので英数とハイフン、かつ端はハイフンでない。
# サービスの pattern は `^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]))$` で、
# **長さの上限は入っていない**（63 オクテットはこの検査では立証されていない）ので
# ルールも文字種と端だけを見る。スキーマはこのプロパティに何の制約も持たない。
violation contains make_diag_full("pf-ses-dkim-signing-selector-charset", "ERROR", name,
	"Properties.DkimSigningAttributes.DomainSigningSelector",
	sprintf("DomainSigningSelector '%v' is not a single DNS label; the identity create fails with \"Value at 'dkimSigningAttributes.domainSigningSelector' failed to satisfy constraint: Member must satisfy regular expression pattern: ^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]))$\"", [s]),
	"Use letters, digits and inner hyphens only (e.g. selector1); no dots, underscores or leading/trailing hyphen",
	"https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_DkimSigningAttributes.html") if {
	some name in resources_of_type("AWS::SES::EmailIdentity")
	s := object.get(_pf_ses_dkim(name), "DomainSigningSelector", null)
	_pf_ses_lit(s)
	not regex.match(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$`, s)
}
