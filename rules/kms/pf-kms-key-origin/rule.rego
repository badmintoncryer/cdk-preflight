package cdk_preflight

import rego.v1

_pf_kmsorg_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kms-key.html"

_pf_kmsorg_fix := "Use Origin AWS_KMS or EXTERNAL (and a non-ML-DSA KeySpec with EXTERNAL); custom key store keys must be created outside CloudFormation"

violation contains make_diag_full("pf-kms-key-origin", "ERROR", name,
	"Properties.Origin",
	sprintf("Origin %s is not supported by AWS::KMS::Key (custom key stores need CustomKeyStoreId, which the resource cannot pass); the handler fails with \"Model validation failed ... #/Origin: failed validation constraint for keyword [enum]\"", [o]),
	_pf_kmsorg_fix, _pf_kmsorg_url) if {
	some name in resources_of_type("AWS::KMS::Key")
	o := resolve(name, "Properties.Origin")
	o in ["AWS_CLOUDHSM", "EXTERNAL_KEY_STORE"]
}

violation contains make_diag_full("pf-kms-key-origin", "ERROR", name,
	"Properties.KeySpec",
	sprintf("KeySpec %s cannot use imported key material; CreateKey fails with \"KeySpec %s is not supported for Origin EXTERNAL\"", [spec, spec]),
	_pf_kmsorg_fix, _pf_kmsorg_url) if {
	some name in resources_of_type("AWS::KMS::Key")
	resolve(name, "Properties.Origin") == "EXTERNAL"
	spec := resolve(name, "Properties.KeySpec")
	is_string(spec)
	startswith(spec, "ML_DSA_")
}
