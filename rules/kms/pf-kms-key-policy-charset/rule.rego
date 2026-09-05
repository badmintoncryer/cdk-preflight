package cdk_preflight

import rego.v1

_pf_kmspc_url := "https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html"

_pf_kmspc_fix := "Keep Sid and other policy text ASCII/Latin-1"

# KeyPolicy arrives as a JSON object or as a JSON string (both are valid CloudFormation).
_pf_kmspc_pol(name) := v if {
	v := object.get(input.resources[name].properties, "KeyPolicy", null)
	is_object(v)
}

_pf_kmspc_pol(name) := v if {
	raw := object.get(input.resources[name].properties, "KeyPolicy", null)
	is_string(raw)
	v := json.unmarshal(raw)
	is_object(v)
}

_pf_kmspc_types := ["AWS::KMS::Key", "AWS::KMS::ReplicaKey"]

violation contains make_diag_full("pf-kms-key-policy-charset", "ERROR", name,
	"Properties.KeyPolicy",
	sprintf("KeyPolicy contains characters outside U+0009/U+000A/U+000D/U+0020-U+00FF (first: '%s'); CreateKey fails with ValidationException on the policy pattern [\\u0009\\u000A\\u000D\\u0020-\\u00FF]+", [bad[0]]),
	_pf_kmspc_fix, _pf_kmspc_url) if {
	some t in _pf_kmspc_types
	some name in resources_of_type(t)
	text := json.marshal(_pf_kmspc_pol(name))
	bad := regex.find_n("[^\t\n\r -\u00ff]", text, 1)
	count(bad) > 0
}
