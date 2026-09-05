package cdk_preflight

import rego.v1

_pf_kmsrot_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kms-key.html"

_pf_kmsrot_fix := "Drop EnableKeyRotation (or set it to false) for asymmetric, HMAC and imported-material keys"

_pf_kmsrot_props(name) := props if {
	props := input.resources[name].properties
	is_object(props)
}

_pf_kmsrot_spec(name) := s if {
	s := resolve(name, "Properties.KeySpec")
	is_string(s)
}

_pf_kmsrot_spec(name) := "SYMMETRIC_DEFAULT" if {
	object.get(_pf_kmsrot_props(name), "KeySpec", "__pf_absent") == "__pf_absent"
}

_pf_kmsrot_on(name) if resolve(name, "Properties.EnableKeyRotation") in {true, "true"}

violation contains make_diag_full("pf-kms-key-rotation", "ERROR", name,
	"Properties.EnableKeyRotation",
	sprintf("automatic rotation is enabled on a %s key; only SYMMETRIC_DEFAULT keys rotate, and the resource handler fails with \"You cannot set the EnableKeyRotation property to true on asymmetric or external keys.\"", [spec]),
	_pf_kmsrot_fix, _pf_kmsrot_url) if {
	some name in resources_of_type("AWS::KMS::Key")
	_pf_kmsrot_on(name)
	spec := _pf_kmsrot_spec(name)
	spec != "SYMMETRIC_DEFAULT"
}

violation contains make_diag_full("pf-kms-key-rotation", "ERROR", name,
	"Properties.EnableKeyRotation",
	"automatic rotation is enabled on a key with Origin EXTERNAL (imported key material); the resource handler fails with \"You cannot set the EnableKeyRotation property to true on asymmetric or external keys.\"",
	_pf_kmsrot_fix, _pf_kmsrot_url) if {
	some name in resources_of_type("AWS::KMS::Key")
	_pf_kmsrot_on(name)
	resolve(name, "Properties.Origin") == "EXTERNAL"
}
