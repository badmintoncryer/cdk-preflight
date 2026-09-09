package cdk_preflight

import rego.v1

_pf_cf_continuous_deployment_header_prefix_fix := "Prefix the header name with aws-cf-cd-"

_pf_cf_continuous_deployment_header_prefix_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-continuousdeploymentpolicy.html"

violation contains make_diag_full("pf-cloudfront-continuous-deployment-header-prefix", "ERROR", name, "Properties.ContinuousDeploymentPolicyConfig.TrafficConfig",
	sprintf("header %v must start with aws-cf-cd-", [h]),
	_pf_cf_continuous_deployment_header_prefix_fix, _pf_cf_continuous_deployment_header_prefix_url) if {
	some name in resources_of_type("AWS::CloudFront::ContinuousDeploymentPolicy")
	tc := object.get(_pf_cflib_props(name, "ContinuousDeploymentPolicyConfig"), "TrafficConfig", null)
	is_object(tc)
	sh := object.get(tc, "SingleHeaderConfig", null)
	is_object(sh)
	h := object.get(sh, "Header", null)
	is_string(h)
	not startswith(lower(h), "aws-cf-cd-")
}
