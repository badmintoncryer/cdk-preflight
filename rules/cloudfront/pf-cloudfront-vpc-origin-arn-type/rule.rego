package cdk_preflight

import rego.v1

_pf_cf_vpc_origin_arn_type_fix := "Use an elasticloadbalancing or ec2 instance ARN"

_pf_cf_vpc_origin_arn_type_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-vpcorigin.html"

violation contains make_diag_full("pf-cloudfront-vpc-origin-arn-type", "ERROR", name, "Properties.VpcOriginEndpointConfig.Arn",
	sprintf("%v is neither a load balancer nor an EC2 instance ARN", [a]),
	_pf_cf_vpc_origin_arn_type_fix, _pf_cf_vpc_origin_arn_type_url) if {
	some name in resources_of_type("AWS::CloudFront::VpcOrigin")
	cfgv := _pf_cflib_props(name, "VpcOriginEndpointConfig")
	a := object.get(cfgv, "Arn", null)
	is_string(a)
	startswith(a, "arn:")
	not regex.match("^arn:[a-z0-9-]+:elasticloadbalancing:", a)
	not regex.match("^arn:[a-z0-9-]+:ec2:[a-z0-9-]*:[0-9]*:instance/", a)
}
