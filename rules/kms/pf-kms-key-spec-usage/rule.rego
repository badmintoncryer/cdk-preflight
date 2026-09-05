package cdk_preflight

import rego.v1

_pf_kmsksu_url := "https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html"

_pf_kmsksu_fix := "Pick a KeyUsage from the table for the KeySpec (and always set KeyUsage for asymmetric and HMAC keys)"

_pf_kmsksu_props(name) := props if {
	props := input.resources[name].properties
	is_object(props)
}

_pf_kmsksu_spec(name) := s if {
	s := resolve(name, "Properties.KeySpec")
	is_string(s)
}

_pf_kmsksu_spec(name) := "SYMMETRIC_DEFAULT" if {
	object.get(_pf_kmsksu_props(name), "KeySpec", "__pf_absent") == "__pf_absent"
}

_pf_kmsksu_allowed := {
	"SYMMETRIC_DEFAULT": ["ENCRYPT_DECRYPT"],
	"HMAC_224": ["GENERATE_VERIFY_MAC"],
	"HMAC_256": ["GENERATE_VERIFY_MAC"],
	"HMAC_384": ["GENERATE_VERIFY_MAC"],
	"HMAC_512": ["GENERATE_VERIFY_MAC"],
	"RSA_2048": ["ENCRYPT_DECRYPT", "SIGN_VERIFY"],
	"RSA_3072": ["ENCRYPT_DECRYPT", "SIGN_VERIFY"],
	"RSA_4096": ["ENCRYPT_DECRYPT", "SIGN_VERIFY"],
	"ECC_NIST_P256": ["SIGN_VERIFY", "KEY_AGREEMENT"],
	"ECC_NIST_P384": ["SIGN_VERIFY", "KEY_AGREEMENT"],
	"ECC_NIST_P521": ["SIGN_VERIFY", "KEY_AGREEMENT"],
	"ECC_NIST_EDWARDS25519": ["SIGN_VERIFY"],
	"ECC_SECG_P256K1": ["SIGN_VERIFY"],
	"ML_DSA_44": ["SIGN_VERIFY"],
	"ML_DSA_65": ["SIGN_VERIFY"],
	"ML_DSA_87": ["SIGN_VERIFY"],
	"SM2": ["ENCRYPT_DECRYPT", "SIGN_VERIFY", "KEY_AGREEMENT"],
}

violation contains make_diag_full("pf-kms-key-spec-usage", "ERROR", name,
	"Properties.KeyUsage",
	sprintf("KeyUsage %s is not valid for KeySpec %s (allowed: %s); CreateKey fails with \"KeyUsage %s is not compatible with KeySpec %s\"", [usage, spec, concat("|", _pf_kmsksu_allowed[spec]), usage, spec]),
	_pf_kmsksu_fix, _pf_kmsksu_url) if {
	some name in resources_of_type("AWS::KMS::Key")
	spec := _pf_kmsksu_spec(name)
	_pf_kmsksu_allowed[spec]
	usage := resolve(name, "Properties.KeyUsage")
	is_string(usage)
	not usage in _pf_kmsksu_allowed[spec]
}

violation contains make_diag_full("pf-kms-key-spec-usage", "ERROR", name,
	"Properties.KeyUsage",
	sprintf("KeySpec %s has no KeyUsage; CreateKey fails with \"You must specify a KeyUsage value for all KMS keys except for symmetric encryption keys.\"", [spec]),
	_pf_kmsksu_fix, _pf_kmsksu_url) if {
	some name in resources_of_type("AWS::KMS::Key")
	spec := _pf_kmsksu_spec(name)
	spec != "SYMMETRIC_DEFAULT"
	object.get(_pf_kmsksu_props(name), "KeyUsage", "__pf_absent") == "__pf_absent"
}
