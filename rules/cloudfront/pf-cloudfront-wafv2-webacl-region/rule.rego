package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudfront-wafv2-webacl-region", "ERROR", name,
	"Properties.DistributionConfig.WebACLId",
	sprintf("A web ACL attached to CloudFront must be created in us-east-1 with scope CLOUDFRONT, but this one is in %s", [region]),
	"Create the WAFv2 web ACL in a us-east-1 stack with scope CLOUDFRONT and reference that ARN",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-wafv2-webacl.html") if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	arn := resolve(name, "Properties.DistributionConfig.WebACLId")
	is_string(arn)
	parts := split(arn, ":")
	count(parts) >= 6
	parts[0] == "arn"
	parts[2] == "wafv2"
	region := parts[3]
	region != ""
	region != "us-east-1"
}
