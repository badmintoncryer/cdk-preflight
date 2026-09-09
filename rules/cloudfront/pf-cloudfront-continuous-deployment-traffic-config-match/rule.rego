package cdk_preflight

import rego.v1

_pf_cf_continuous_deployment_traffic_config_match_fix := "Pair Type SingleWeight with SingleWeightConfig, and SingleHeader with SingleHeaderConfig"

_pf_cf_continuous_deployment_traffic_config_match_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-continuousdeploymentpolicy.html"

violation contains make_diag_full("pf-cloudfront-continuous-deployment-traffic-config-match", "ERROR", name, "Properties.ContinuousDeploymentPolicyConfig.TrafficConfig",
	"TrafficConfig.Type is SingleWeight but SingleWeightConfig is missing",
	_pf_cf_continuous_deployment_traffic_config_match_fix, _pf_cf_continuous_deployment_traffic_config_match_url) if {
	some name in resources_of_type("AWS::CloudFront::ContinuousDeploymentPolicy")
	tc := object.get(_pf_cflib_props(name, "ContinuousDeploymentPolicyConfig"), "TrafficConfig", null)
	is_object(tc)
	object.get(tc, "Type", null) == "SingleWeight"
	object.get(tc, "SingleWeightConfig", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-cloudfront-continuous-deployment-traffic-config-match", "ERROR", name, "Properties.ContinuousDeploymentPolicyConfig.TrafficConfig",
	"TrafficConfig.Type is SingleHeader but SingleHeaderConfig is missing",
	_pf_cf_continuous_deployment_traffic_config_match_fix, _pf_cf_continuous_deployment_traffic_config_match_url) if {
	some name in resources_of_type("AWS::CloudFront::ContinuousDeploymentPolicy")
	tc := object.get(_pf_cflib_props(name, "ContinuousDeploymentPolicyConfig"), "TrafficConfig", null)
	is_object(tc)
	object.get(tc, "Type", null) == "SingleHeader"
	object.get(tc, "SingleHeaderConfig", "__pf_absent") == "__pf_absent"
}
