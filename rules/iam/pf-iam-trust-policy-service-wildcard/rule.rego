package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iam-trust-policy-service-wildcard", "ERROR", name,
	sprintf("%s.Statement.%d.Principal.Service", [path, i]),
	sprintf("Service principal '%s' holds a wildcard; IAM rejects the role with \"Invalid principal in policy\" — a service principal is matched literally, never by pattern", [v]),
	"Name each service principal in full (lambda.amazonaws.com); to trust any principal use \"Principal\": {\"AWS\": \"*\"} with a Condition instead",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html") if {
	some [name, path, d] in _pf_iamlib_trusts
	some [i, s] in _pf_iamlib_stmts(d)
	is_object(s)
	some [t, v] in _pf_iamlib_principals(s, "Principal")
	t == "Service"
	is_string(v)
	regex.match(`[*?]`, v)
}
