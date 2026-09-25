package cdk_preflight

import rego.v1

# Type and body are validated independently by CFN: Policy is just a 1-20480
# character string in the schema, so nothing below this line is visible to any
# other layer. The two SecurityPolicy types disagree on BOTH the top-level JSON
# type and the accepted keys, and the server rejects each separately.

_pf_aoss_encshape_fix := "Give an encryption policy a JSON object {\"Rules\": [...], \"AWSOwnedKey\": true}; AllowFromPublic, SourceVPCEs and SourceServices belong to a Type: network policy"

violation contains make_diag_full("pf-aoss-security-policy-encryption-body-shape", "ERROR", name,
	"Properties.Policy",
	"the encryption policy document is not a JSON object; CreateSecurityPolicy answers \"Policy json is invalid, error: [$: array found, object expected]\"",
	_pf_aoss_encshape_fix, "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-opensearchserverless-securitypolicy.html") if {
	some name in _pf_aoss_enc
	d := _pf_aoss_doc(name)
	not is_object(d)
}

violation contains make_diag_full("pf-aoss-security-policy-encryption-body-shape", "ERROR", name,
	sprintf("Properties.Policy.%v", [k]),
	sprintf("%v is a network policy key but this policy has Type encryption; CreateSecurityPolicy answers \"Policy json is invalid, error: [$.%v: is not defined in the schema and the schema does not allow additional properties]\"", [k, k]),
	_pf_aoss_encshape_fix, "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-opensearchserverless-securitypolicy.html") if {
	some name in _pf_aoss_enc
	d := _pf_aoss_doc(name)
	is_object(d)
	some k in _pf_aoss_net_only_keys
	object.get(d, k, "__pf_absent") != "__pf_absent"
}
