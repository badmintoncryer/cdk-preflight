package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iam-policy-resource-partition", "ERROR", name,
	sprintf("%s.Statement.%d", [path, i]),
	sprintf("Resource ARN '%s' names partition '%s' but the stack deploys into '%s'; IAM rejects the document with \"Partition ... is not valid for resource\"", [v, part, _pf_iamlib_partition]),
	sprintf("Use the deploy partition (arn:%s:...) or build the ARN from the AWS::Partition pseudo parameter", [_pf_iamlib_partition]),
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html") if {
	some [name, path, d] in _pf_iamlib_all
	some [i, s] in _pf_iamlib_stmts(d)
	is_object(s)
	some v in _pf_iamlib_resources(s)
	is_string(v)
	startswith(v, "arn:")
	parts := split(v, ":")
	count(parts) >= 6
	part := parts[1]
	part != _pf_iamlib_partition
	not regex.match(`[*?]`, part)
}
