package cdk_preflight

import rego.v1

# The mirror of pf-aoss-security-policy-encryption-body-shape. The developer
# guide shows one rule block for a network policy, which reads like the whole
# document; the server wants that block inside an array.

_pf_aoss_netshape_fix := "Give a network policy a JSON array [{\"Rules\": [...], \"AllowFromPublic\": true}]; AWSOwnedKey and KmsARN belong to a Type: encryption policy"

violation contains make_diag_full("pf-aoss-security-policy-network-body-shape", "ERROR", name,
	"Properties.Policy",
	"the network policy document is not a JSON array; CreateSecurityPolicy answers \"Policy json is invalid, error: [$: object found, array expected]\"",
	_pf_aoss_netshape_fix, "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-opensearchserverless-securitypolicy.html") if {
	some name in _pf_aoss_net
	d := _pf_aoss_doc(name)
	not is_array(d)
}

violation contains make_diag_full("pf-aoss-security-policy-network-body-shape", "ERROR", name,
	sprintf("%v.%v", [p, k]),
	sprintf("%v is an encryption policy key but this policy has Type network; CreateSecurityPolicy answers \"Policy json is invalid, error: [$[0].%v: is not defined in the schema and the schema does not allow additional properties]\"", [k, k]),
	_pf_aoss_netshape_fix, "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-opensearchserverless-securitypolicy.html") if {
	some name in _pf_aoss_net
	some [p, b] in _pf_aoss_blocks_at(name)
	some k in _pf_aoss_enc_only_keys
	object.get(b, k, "__pf_absent") != "__pf_absent"
}
