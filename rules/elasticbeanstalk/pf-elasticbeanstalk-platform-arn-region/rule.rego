package cdk_preflight

import rego.v1

_pf_eb_platform_arn_region_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_CreateConfigurationTemplate.html"

_pf_eb_platform_arn_region_region := r if {
	r := data.cdk_preflight.deploy_region
	is_string(r)
	r != ""
}

violation contains make_diag_full("pf-elasticbeanstalk-platform-arn-region", "ERROR", name, "Properties.PlatformArn",
	sprintf("PlatformArn points at %v but the stack is deployed to %v; Elastic Beanstalk platforms are region-scoped and an AWS platform ARN from another region is rejected", [parts[3], _pf_eb_platform_arn_region_region]),
	sprintf("Use the platform ARN of %v", [_pf_eb_platform_arn_region_region]), _pf_eb_platform_arn_region_url) if {
	some name in _pf_eblib_res
	arn := object.get(_pf_eblib_props(name), "PlatformArn", null)
	is_string(arn)
	parts := split(arn, ":")
	count(parts) >= 6
	parts[2] == "elasticbeanstalk"
	parts[3] != ""
	parts[4] == ""
	parts[3] != _pf_eb_platform_arn_region_region
}
