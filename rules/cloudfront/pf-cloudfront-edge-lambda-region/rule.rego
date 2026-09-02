package cdk_preflight

import rego.v1

_pf_cf_edgeregion_fix := "Create the Lambda@Edge function in us-east-1 (cloudfront.experimental.EdgeFunction does this for you) and associate that version's ARN"

_pf_cf_edgeregion_url := "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/lambda-at-edge-function-restrictions.html"

_pf_cf_edgeregion_behaviors(name) := array.concat(
	[{"path": "Properties.DistributionConfig.DefaultCacheBehavior"} |
		some _ in flatten_list(name, "Properties.DistributionConfig.DefaultCacheBehavior")],
	[{"path": sprintf("Properties.DistributionConfig.CacheBehaviors.%d", [it.index])} |
		some it in flatten_list(name, "Properties.DistributionConfig.CacheBehaviors")],
)

violation contains make_diag_full("pf-cloudfront-edge-lambda-region", "ERROR", name,
	sprintf("%s.LambdaFunctionAssociations.%d.LambdaFunctionARN", [b.path, a.index]),
	sprintf("Lambda@Edge functions must live in us-east-1, but this function is in %s", [region]),
	_pf_cf_edgeregion_fix, _pf_cf_edgeregion_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some b in _pf_cf_edgeregion_behaviors(name)
	some a in flatten_list(name, sprintf("%s.LambdaFunctionAssociations", [b.path]))
	arn := object.get(a.value, "LambdaFunctionARN", null)
	is_string(arn)
	parts := split(arn, ":")
	count(parts) >= 7
	parts[0] == "arn"
	parts[2] == "lambda"
	region := parts[3]
	region != ""
	region != "us-east-1"
}
