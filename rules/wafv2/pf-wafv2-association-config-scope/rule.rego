package cdk_preflight

import rego.v1

_pf_wafacs_url := "https://docs.aws.amazon.com/waf/latest/APIReference/API_AssociationConfig.html"

_pf_wafacs_fix := "Use the CLOUDFRONT key only in CLOUDFRONT-scoped web ACLs and the regional keys (API_GATEWAY, COGNITO_USER_POOL, APP_RUNNER_SERVICE, VERIFIED_ACCESS_INSTANCE) only in REGIONAL ones"

_pf_wafacs_keys contains [name, k] if {
	some name in resources_of_type("AWS::WAFv2::WebACL")
	rb := input.resources[name].properties.AssociationConfig.RequestBody
	is_object(rb)
	some k in object.keys(rb)
}

violation contains make_diag_full("pf-wafv2-association-config-scope", "ERROR", name, sprintf("Properties.AssociationConfig.RequestBody.%s", [k]),
	sprintf("key %s is not valid for a %s-scoped web ACL; CreateWebACL fails with \"The scope is not valid.\"", [k, scope]),
	_pf_wafacs_fix, _pf_wafacs_url) if {
	some [name, k] in _pf_wafacs_keys
	scope := _pf_waflib_scope(name)
	_pf_wafacs_mismatch(k, scope)
}

_pf_wafacs_mismatch(k, scope) if {
	k == "CLOUDFRONT"
	scope != "CLOUDFRONT"
}

_pf_wafacs_mismatch(k, scope) if {
	k != "CLOUDFRONT"
	scope == "CLOUDFRONT"
}
