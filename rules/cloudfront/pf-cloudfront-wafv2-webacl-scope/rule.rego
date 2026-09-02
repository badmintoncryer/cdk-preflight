package cdk_preflight

import rego.v1

# A WAFv2 ARN carries its scope in the resource segment:
#   arn:aws:wafv2:us-east-1:123456789012:global/webacl/name/id    (CLOUDFRONT)
#   arn:aws:wafv2:ap-northeast-1:123456789012:regional/webacl/... (REGIONAL)
# CloudFront accepts only the global form. Checking the region alone would miss
# a REGIONAL web ACL that happens to have been created in us-east-1, which is
# the easy mistake to make.
violation contains make_diag_full("pf-cloudfront-wafv2-webacl-scope", "ERROR", name,
	"Properties.DistributionConfig.WebACLId",
	sprintf("CloudFront only accepts a globally scoped web ACL, but this ARN is scoped '%s'", [scope]),
	"Create the web ACL with scope CLOUDFRONT in us-east-1 (wafv2.CfnWebACL with scope: 'CLOUDFRONT') and reference that ARN",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-wafv2-webacl.html") if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	arn := resolve(name, "Properties.DistributionConfig.WebACLId")
	is_string(arn)
	parts := split(arn, ":")
	count(parts) >= 6
	parts[0] == "arn"
	parts[2] == "wafv2"
	segments := split(parts[5], "/")
	scope := segments[0]
	scope != "global"
}
