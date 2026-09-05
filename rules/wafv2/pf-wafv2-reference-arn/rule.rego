package cdk_preflight

import rego.v1

_pf_wafra_url := "https://docs.aws.amazon.com/waf/latest/developerguide/waf-ip-set-managing.html"

_pf_wafra_fix := "Reference an entity of the same Scope created in the same account and region (Fn::GetAtt X.Arn of a resource in this stack, or an ARN whose global/regional segment and region match the web ACL)"

_pf_wafra_refs contains [name, i, p, kind, arn] if {
	some [name, i, p, kind, body] in _pf_waflib_leaves
	_pf_waflib_ref_kinds[kind]
	arn := body.Arn
}

_pf_wafra_path(i, p, kind) := sprintf("%s.Arn", [_pf_waflib_path(i, array.concat(p, [kind]))])

_pf_wafra_res(parts) := split(parts[5], "/")

_pf_wafra_msg := "the create call fails with \"The ARN isn't valid. A valid ARN begins with arn: and includes other information separated by colons or slashes.\""

# literal ARN that is not a wafv2 ARN of the expected entity kind
violation contains make_diag_full("pf-wafv2-reference-arn", "ERROR", name, _pf_wafra_path(i, p, kind),
	sprintf("'%s' is not the ARN of a WAFv2 %s; %s", [arn, _pf_waflib_ref_kinds[kind], _pf_wafra_msg]),
	_pf_wafra_fix, _pf_wafra_url) if {
	some [name, i, p, kind, arn] in _pf_wafra_refs
	is_string(arn)
	not _pf_wafra_well_formed(arn, _pf_waflib_ref_kinds[kind])
}

_pf_wafra_well_formed(arn, res) if {
	parts := _pf_waflib_arn(arn)
	parts[2] == "wafv2"
	r := _pf_wafra_res(parts)
	r[0] in {"global", "regional"}
	r[1] == res
}

# global/regional segment vs the container's Scope
violation contains make_diag_full("pf-wafv2-reference-arn", "ERROR", name, _pf_wafra_path(i, p, kind),
	sprintf("scope '%s' entity referenced from a %s-scoped web ACL; %s", [r[0], scope, _pf_wafra_msg]),
	_pf_wafra_fix, _pf_wafra_url) if {
	some [name, i, p, kind, arn] in _pf_wafra_refs
	_pf_wafra_well_formed(arn, _pf_waflib_ref_kinds[kind])
	r := _pf_wafra_res(_pf_waflib_arn(arn))
	scope := _pf_waflib_scope(name)
	_pf_wafra_expected[scope] != r[0]
}

_pf_wafra_expected := {"CLOUDFRONT": "global", "REGIONAL": "regional"}

# region of the ARN vs where the container lives (needs the deploy environment for REGIONAL)
violation contains make_diag_full("pf-wafv2-reference-arn", "ERROR", name, _pf_wafra_path(i, p, kind),
	sprintf("ARN region '%s' differs from the web ACL region '%s'; %s", [parts[3], region, _pf_wafra_msg]),
	_pf_wafra_fix, _pf_wafra_url) if {
	some [name, i, p, kind, arn] in _pf_wafra_refs
	_pf_wafra_well_formed(arn, _pf_waflib_ref_kinds[kind])
	parts := _pf_waflib_arn(arn)
	region := _pf_waflib_region(name)
	parts[3] != region
}

violation contains make_diag_full("pf-wafv2-reference-arn", "ERROR", name, _pf_wafra_path(i, p, kind),
	sprintf("ARN belongs to account %s but the stack deploys to account %s; the create call fails with AccessDenied", [parts[4], account]),
	_pf_wafra_fix, _pf_wafra_url) if {
	account := data.cdk_preflight.deploy_account
	some [name, i, p, kind, arn] in _pf_wafra_refs
	_pf_wafra_well_formed(arn, _pf_waflib_ref_kinds[kind])
	parts := _pf_waflib_arn(arn)
	parts[4] != account
}

# in-template reference: wrong resource type, or a different Scope
violation contains make_diag_full("pf-wafv2-reference-arn", "ERROR", name, _pf_wafra_path(i, p, kind),
	sprintf("references %s, which is not an %s; %s", [x, _pf_waflib_ref_types[kind], _pf_wafra_msg]),
	_pf_wafra_fix, _pf_wafra_url) if {
	some [name, i, p, kind, arn] in _pf_wafra_refs
	x := _pf_waflib_getatt(arn)
	input.resources[x]
	not x in resources_of_type(_pf_waflib_ref_types[kind])
}

violation contains make_diag_full("pf-wafv2-reference-arn", "ERROR", name, _pf_wafra_path(i, p, kind),
	sprintf("references %s whose Scope is %s, but this container is %s; %s", [x, other, scope, _pf_wafra_msg]),
	_pf_wafra_fix, _pf_wafra_url) if {
	some [name, i, p, kind, arn] in _pf_wafra_refs
	x := _pf_waflib_getatt(arn)
	x in resources_of_type(_pf_waflib_ref_types[kind])
	scope := _pf_waflib_scope(name)
	other := _pf_waflib_scope(x)
	other != scope
}
