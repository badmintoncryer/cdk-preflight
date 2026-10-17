package cdk_preflight

import rego.v1

# Shared helpers for rules/vpclattice/*.

_pf_vpcl_tgs := resources_of_type("AWS::VpcLattice::TargetGroup")

_pf_vpcl_tgtype(name) := t if {
	t := resolve(name, "Properties.Type")
	is_string(t)
}

_pf_vpcl_tgs_of(t) := {n |
	some n in _pf_vpcl_tgs
	_pf_vpcl_tgtype(n) == t
}

# Present and not removed by AWS::NoValue.
_pf_vpcl_has(name, path) if {
	v := resolve(name, path)
	v != null
}

_pf_vpcl_str(name, path, _) := v if {
	v := resolve(name, path)
	is_string(v)
}

_pf_vpcl_str(name, path, def) := def if not _pf_vpcl_has(name, path)

# Literal Targets[].Id (a Ref / Fn::GetAtt stays an object and is skipped).
_pf_vpcl_target_id(t) := id if {
	id := object.get(t.value, "Id", null)
	is_string(id)
}

# ARN fields; undefined for non-ARNs.
_pf_vpcl_arn(s) := p if {
	is_string(s)
	p := split(s, ":")
	count(p) >= 6
	p[0] == "arn"
	p[3] != ""
}

# A space or a non-ASCII character (StartDomainVerification / CreateService:
# "Domain names must contain only ASCII characters").
_pf_vpcl_bad_domain(d) if {
	is_string(d)
	regex.match(`[^\x21-\x7e]`, d)
}

# Raw property value at a key path ("__pf_absent" when missing). Intrinsics stay
# as marker objects here, so an equality test against a literal ({} etc.) is
# never fooled by a Ref / Fn::If.
_pf_vpcl_raw(name, keys) := v if {
	props := input.resources[name].properties
	is_object(props)
	v := object.get(props, keys, "__pf_absent")
}

# Forward entries (at path ...Forward.TargetGroups) that reference a target
# group in the same template: [index, target group logical id].
_pf_vpcl_fwd_tgs(name, path) := {[i, tg] |
	some it in flatten_list(name, path)
	i := it.index
	tg := resolve(name, sprintf("%s.%d.TargetGroupIdentifier", [path, i]))
	tg in _pf_vpcl_tgs
}

# A literal string or number (resolve() hands back logical ids as strings too).
_pf_vpcl_lit(v) if is_string(v)

_pf_vpcl_lit(v) if is_number(v)
