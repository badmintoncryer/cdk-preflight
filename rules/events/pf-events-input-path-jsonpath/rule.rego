package cdk_preflight

import rego.v1

# "InputPath for target <id> is invalid." — EventBridge takes a JSON path
# rooted at $, and the same check runs over every InputPathsMap value.
# Measured 2026-09-07, events:PutTargets, us-east-1, symmetrically for
# InputPath and for every InputPathsMap value: a path without the leading $
# is refused, and quoted bracket notation ($.detail['key']) is refused even
# though it is legal JSONPath. Numeric indices ($.detail.a[0]) and a bare $
# ARE accepted, so only brackets holding a quote are reported.
_pf_evipp_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-target.html"

# An InputPathsMap that is an unresolvable intrinsic is normalized to an
# object of __-prefixed marker keys; its values are not paths, so skip it.
_pf_evipp_plain(pm) if {
	every k, v in pm {
		not startswith(k, "__")
	}
}

_pf_evipp_bad(p) if not startswith(p, "$")

_pf_evipp_bad(p) if regex.match(`\[\s*['"]`, p)

violation contains make_diag_full("pf-events-input-path-jsonpath", "ERROR", name,
	sprintf("Properties.Targets.%d.InputPath", [t.index]),
	sprintf("'%s' is not a supported JSON path; PutTargets fails with \"InputPath for target %s is invalid\" (paths start at $ and use dot notation)", [p, tid]),
	"Write the path as $.a.b",
	_pf_evipp_url) if {
	some name in resources_of_type("AWS::Events::Rule")
	some t in flatten_list(name, "Properties.Targets")
	is_object(t.value)
	p := object.get(t.value, "InputPath", null)
	is_string(p)
	_pf_evipp_bad(p)
	tid := object.get(t.value, "Id", "<target>")
}

violation contains make_diag_full("pf-events-input-path-jsonpath", "ERROR", name,
	sprintf("Properties.Targets.%d.InputTransformer.InputPathsMap.%s", [t.index, k]),
	sprintf("'%s' is not a supported JSON path; PutTargets fails with \"InputPath for target %s is invalid\" (paths start at $ and use dot notation)", [p, tid]),
	"Write the path as $.a.b",
	_pf_evipp_url) if {
	some name in resources_of_type("AWS::Events::Rule")
	some t in flatten_list(name, "Properties.Targets")
	is_object(t.value)
	it := object.get(t.value, "InputTransformer", null)
	is_object(it)
	pm := object.get(it, "InputPathsMap", null)
	is_object(pm)
	_pf_evipp_plain(pm)
	some k, p in pm
	is_string(p)
	_pf_evipp_bad(p)
	tid := object.get(t.value, "Id", "<target>")
}
