package cdk_preflight

import rego.v1

_pf_lekkp_fix := "Add a key policy statement allowing lambda.amazonaws.com to kms:Decrypt"

_pf_lekkp_url := "https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventfiltering.html"

_pf_lekkp_allows(k) if {
	some st in _pf_lam_list(object.get(_pf_lam_obj(_pf_lam_props(k), "KeyPolicy"), "Statement", []))
	is_object(st)
	object.get(st, "Effect", "") == "Allow"
	some p in _pf_lam_list(object.get(_pf_lam_obj(st, "Principal"), "Service", []))
	p == "lambda.amazonaws.com"
}

violation contains make_diag_full("pf-lambda-esm-kms-key-policy-lambda-principal", "ERROR", k,
	"Properties.KeyPolicy",
	sprintf("key '%v' encrypts filter criteria but its policy never allows the lambda.amazonaws.com service principal; the mapping create fails on kms:Decrypt", [k]),
	_pf_lekkp_fix, _pf_lekkp_url) if {
	some name in _pf_lam_esm
	k := resolve(name, "Properties.KmsKeyArn")
	k in resources_of_type("AWS::KMS::Key")
	not _pf_lekkp_allows(k)
}
