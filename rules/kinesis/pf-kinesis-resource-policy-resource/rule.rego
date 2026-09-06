package cdk_preflight

import rego.v1

_pf_kinrpr_fix := "Write the same ARN as ResourceArn in every statement Resource — Kinesis rejects wildcards and any other ARN"

# Both sides go through resolve(), so a GetAtt-wired ResourceArn and a
# GetAtt-wired Resource compare equal as the same logical id.
violation contains make_diag_full("pf-kinesis-resource-policy-resource", "ERROR", name,
	sprintf("Properties.ResourcePolicy.Statement.%v.Resource", [i]),
	sprintf("statement %v targets '%v' but the policy is attached to '%v'; PutResourcePolicy fails with \"The resource policy's resource must be the same as the resource ARN.\"", [i, r, ra]),
	_pf_kinrpr_fix, "https://docs.aws.amazon.com/kinesis/latest/APIReference/API_PutResourcePolicy.html") if {
	some [name, i, s] in _pf_kinlib_statements
	ra := resolve(name, "Properties.ResourceArn")
	is_string(ra)
	is_string(object.get(s, "Resource", null))
	r := resolve(name, sprintf("Properties.ResourcePolicy.Statement.%v.Resource", [i]))
	is_string(r)
	r != ra
}

violation contains make_diag_full("pf-kinesis-resource-policy-resource", "ERROR", name,
	sprintf("Properties.ResourcePolicy.Statement.%v.Resource.%v", [i, j]),
	sprintf("statement %v targets '%v' but the policy is attached to '%v'; PutResourcePolicy fails with \"The resource policy's resource must be the same as the resource ARN.\"", [i, r, ra]),
	_pf_kinrpr_fix, "https://docs.aws.amazon.com/kinesis/latest/APIReference/API_PutResourcePolicy.html") if {
	some [name, i, s] in _pf_kinlib_statements
	ra := resolve(name, "Properties.ResourceArn")
	is_string(ra)
	rs := object.get(s, "Resource", null)
	is_array(rs)
	some j, _ in rs
	r := resolve(name, sprintf("Properties.ResourcePolicy.Statement.%v.Resource.%v", [i, j]))
	is_string(r)
	r != ra
}
