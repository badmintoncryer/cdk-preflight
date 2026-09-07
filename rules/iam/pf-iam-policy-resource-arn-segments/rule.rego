package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iam-policy-resource-arn-segments", "ERROR", name,
	sprintf("%s.Statement.%d", [path, i]),
	sprintf("Resource ARN '%s' has %d colon-separated segments; an ARN has six (arn:partition:service:region:account:resource) and IAM rejects the document with \"The policy failed legacy parsing\"", [v, count(split(v, ":"))]),
	"Keep the empty segments: an S3 bucket is arn:aws:s3:::bucket, not arn:aws:s3:bucket",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html") if {
	some [name, path, d] in _pf_iamlib_all
	some [i, s] in _pf_iamlib_stmts(d)
	is_object(s)
	some v in _pf_iamlib_resources(s)
	is_string(v)
	startswith(v, "arn:")
	count(split(v, ":")) < 6
}
