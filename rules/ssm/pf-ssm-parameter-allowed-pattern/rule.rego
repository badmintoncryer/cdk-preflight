package cdk_preflight

import rego.v1

_pf_ssmap_url := "https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_PutParameter.html"

_pf_ssmap_fix := "Make the Value match AllowedPattern, or fix the pattern"

_pf_ssmap_items(name) := split(v, ",") if {
	resolve(name, "Properties.Type") == "StringList"
	v := resolve(name, "Properties.Value")
	is_string(v)
}

_pf_ssmap_items(name) := [v] if {
	resolve(name, "Properties.Type") != "StringList"
	v := resolve(name, "Properties.Value")
	is_string(v)
}

# ponytail: only patterns the Rust regex engine accepts are checked (Java-only syntax such as
# lookaround is skipped rather than guessed at)
violation contains make_diag_full("pf-ssm-parameter-allowed-pattern", "ERROR", name,
	"Properties.Value",
	sprintf("value '%s' does not match AllowedPattern '%s'; PutParameter fails with \"Parameter value, cannot be validated against allowedPattern: %s\"", [item, pat, pat]),
	_pf_ssmap_fix, _pf_ssmap_url) if {
	some name in resources_of_type("AWS::SSM::Parameter")
	pat := resolve(name, "Properties.AllowedPattern")
	is_string(pat)
	regex.is_valid(pat)
	some item in _pf_ssmap_items(name)
	not regex.match(pat, item)
}
