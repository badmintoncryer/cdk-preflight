package cdk_preflight

import rego.v1

_pf_cf_edgever_fix := "Associate a version ARN (in the CDK, fn.currentVersion.edgeArn) instead of the unqualified function ARN, an alias, or $LATEST"

_pf_cf_edgever_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cloudfront-distribution-lambdafunctionassociation.html"

_pf_cf_edgever_behaviors(name) := array.concat(
	[{"path": "Properties.DistributionConfig.DefaultCacheBehavior"} |
		some _ in flatten_list(name, "Properties.DistributionConfig.DefaultCacheBehavior")],
	[{"path": sprintf("Properties.DistributionConfig.CacheBehaviors.%d", [it.index])} |
		some it in flatten_list(name, "Properties.DistributionConfig.CacheBehaviors")],
)

# Lambda ARNs split into 7 segments when unqualified
# (arn:partition:lambda:region:account:function:name) and 8 when a version or
# alias qualifier is appended. Only an all-digit qualifier is a version.
_pf_cf_edgever_arns(name) := [{"path": path, "arn": arn, "parts": parts} |
	some b in _pf_cf_edgever_behaviors(name)
	some a in flatten_list(name, sprintf("%s.LambdaFunctionAssociations", [b.path]))
	arn := object.get(a.value, "LambdaFunctionARN", null)
	is_string(arn)
	parts := split(arn, ":")
	parts[0] == "arn"
	parts[2] == "lambda"
	parts[5] == "function"
	path := sprintf("%s.LambdaFunctionAssociations.%d.LambdaFunctionARN", [b.path, a.index])
]

violation contains make_diag_full("pf-cloudfront-edge-lambda-version", "ERROR", name, it.path,
	"Lambda@Edge requires a version-qualified function ARN, but this ARN has no qualifier",
	_pf_cf_edgever_fix, _pf_cf_edgever_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some it in _pf_cf_edgever_arns(name)
	count(it.parts) == 7
}

violation contains make_diag_full("pf-cloudfront-edge-lambda-version", "ERROR", name, it.path,
	sprintf("Lambda@Edge requires a version-qualified function ARN, but '%s' is an alias or $LATEST", [qualifier]),
	_pf_cf_edgever_fix, _pf_cf_edgever_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some it in _pf_cf_edgever_arns(name)
	count(it.parts) == 8
	qualifier := it.parts[7]
	not regex.match("^[0-9]+$", qualifier)
}
