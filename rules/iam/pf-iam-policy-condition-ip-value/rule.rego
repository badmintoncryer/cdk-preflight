package cdk_preflight

import rego.v1

_pf_iamcip_ok(v) if regex.match(`^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(/(3[0-2]|[12]?[0-9]))?$`, v)

_pf_iamcip_ok(v) if regex.match(`^[0-9A-Fa-f:]*:[0-9A-Fa-f:]*(/(12[0-8]|1[01][0-9]|[1-9]?[0-9]))?$`, v)

violation contains make_diag_full("pf-iam-policy-condition-ip-value", "ERROR", name,
	sprintf("%s.Statement.%d.Condition.%s", [path, i, op]),
	sprintf("Condition operator '%s' takes an IP address or CIDR block; '%s' is neither and IAM rejects the document with \"The policy failed legacy parsing\"", [op, v]),
	"Write the value in CIDR form (203.0.113.0/24) or as a bare address; host names and out-of-range octets are rejected",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html") if {
	some [name, path, d] in _pf_iamlib_all
	some [i, s] in _pf_iamlib_stmts(d)
	is_object(s)
	some [op, _, raw] in _pf_iamlib_conds(s)
	_pf_iamlib_op_root(op) in {"IpAddress", "NotIpAddress"}
	some v in _pf_iamlib_list(raw)
	is_string(v)
	not _pf_iamcip_ok(v)
}
