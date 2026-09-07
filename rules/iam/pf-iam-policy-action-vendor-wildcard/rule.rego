package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iam-policy-action-vendor-wildcard", "ERROR", name,
	sprintf("%s.Statement.%d", [path, i]),
	sprintf("Action '%s' puts a wildcard in the service prefix; IAM rejects the document with \"Action vendors (e.g., aws, ec2, etc.) must not contain wildcards.\"", [v]),
	"Name the service exactly (s3:*, ec2:Describe*); only the action half after the colon may hold wildcards, and a bare \"*\" covers every service",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html") if {
	some [name, path, d] in _pf_iamlib_all
	some [i, s] in _pf_iamlib_stmts(d)
	is_object(s)
	some v in _pf_iamlib_actions(s)
	is_string(v)
	parts := split(v, ":")
	count(parts) >= 2
	regex.match(`[*?]`, parts[0])
}
