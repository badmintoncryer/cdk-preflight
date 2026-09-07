package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iam-policy-resource-service-wildcard", "ERROR", name,
	sprintf("%s.Statement.%d", [path, i]),
	sprintf("Resource ARN '%s' puts a wildcard in the service segment; IAM rejects the document with \"Resource vendor must be fully qualified and cannot contain regexes.\"", [v]),
	"Name the service exactly and wildcard the resource half instead (arn:aws:s3:::bucket/*), or use \"*\" for every resource",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html") if {
	some [name, path, d] in _pf_iamlib_all
	some [i, s] in _pf_iamlib_stmts(d)
	is_object(s)
	some v in _pf_iamlib_resources(s)
	is_string(v)
	startswith(v, "arn:")
	parts := split(v, ":")
	count(parts) >= 6
	regex.match(`[*?]`, parts[2])
}
