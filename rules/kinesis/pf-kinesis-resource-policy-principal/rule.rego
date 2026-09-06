package cdk_preflight

import rego.v1

_pf_kinrpp_fix := "Name the sharing account or role in Principal; NotPrincipal is rejected outright"

violation contains make_diag_full("pf-kinesis-resource-policy-principal", "ERROR", name,
	sprintf("Properties.ResourcePolicy.Statement.%v", [i]),
	sprintf("statement %v has no Principal; PutResourcePolicy fails with \"Policy validation error: Missing required field Principal\"", [i]),
	_pf_kinrpp_fix, "https://docs.aws.amazon.com/kinesis/latest/APIReference/API_PutResourcePolicy.html") if {
	some [name, i, s] in _pf_kinlib_statements
	not _pf_kinlib_has(s, "Principal")
	not _pf_kinlib_has(s, "NotPrincipal")
}

violation contains make_diag_full("pf-kinesis-resource-policy-principal", "ERROR", name,
	sprintf("Properties.ResourcePolicy.Statement.%v.NotPrincipal", [i]),
	sprintf("statement %v uses NotPrincipal; PutResourcePolicy fails with \"Policy validation error: Has prohibited field NotPrincipal\"", [i]),
	_pf_kinrpp_fix, "https://docs.aws.amazon.com/kinesis/latest/APIReference/API_PutResourcePolicy.html") if {
	some [name, i, s] in _pf_kinlib_statements
	_pf_kinlib_has(s, "NotPrincipal")
}
