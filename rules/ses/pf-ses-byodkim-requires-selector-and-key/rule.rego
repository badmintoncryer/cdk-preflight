package cdk_preflight

import rego.v1

# BYODKIM は selector と秘密鍵の組で成り立つので片方だけでは identity が作れない。
# 値ではなく存在を見るのは、鍵を Secrets Manager の動的参照で渡す書き方
# （`{{resolve:secretsmanager:...}}`）でも「書いてある」ことは分かるから。
_pf_sesbdk_pairs := [
	["DomainSigningSelector", "DomainSigningPrivateKey"],
	["DomainSigningPrivateKey", "DomainSigningSelector"],
]

violation contains make_diag_full("pf-ses-byodkim-requires-selector-and-key", "ERROR", name,
	"Properties.DkimSigningAttributes",
	sprintf("DkimSigningAttributes sets %v without %v; the identity create fails with \"When using Bring Your Own DKIM, you must provide both DomainSigningSelector and DomainSigningPrivateKey.\"", [have, missing]),
	sprintf("Set DkimSigningAttributes.%v as well, or drop %v and let SES manage the keys (Easy DKIM)", [missing, have]),
	"https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_DkimSigningAttributes.html") if {
	some name in resources_of_type("AWS::SES::EmailIdentity")
	some pair in _pf_sesbdk_pairs
	have := pair[0]
	missing := pair[1]
	_pf_ses_dkim_set(name, have)
	not _pf_ses_dkim_set(name, missing)
}
