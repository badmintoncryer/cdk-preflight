package cdk_preflight

import rego.v1

_pf_cf_public_key_pem_format_fix := "Paste the PEM block, including the BEGIN PUBLIC KEY header"

_pf_cf_public_key_pem_format_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-publickey.html"

violation contains make_diag_full("pf-cloudfront-public-key-pem-format", "ERROR", name, "Properties.PublicKeyConfig.EncodedKey",
	"EncodedKey is not a PEM-encoded public key (no -----BEGIN PUBLIC KEY----- header)",
	_pf_cf_public_key_pem_format_fix, _pf_cf_public_key_pem_format_url) if {
	some name in resources_of_type("AWS::CloudFront::PublicKey")
	cfgv := _pf_cflib_props(name, "PublicKeyConfig")
	v := object.get(cfgv, "EncodedKey", null)
	is_string(v)
	v != ""
	not startswith(v, "-----BEGIN PUBLIC KEY-----")
}
