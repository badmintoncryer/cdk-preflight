package cdk_preflight

import rego.v1

_pf_cf_continuous_deployment_weight_range_fix := "Use a weight of 0.15 or lower"

_pf_cf_continuous_deployment_weight_range_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-continuousdeploymentpolicy.html"

violation contains make_diag_full("pf-cloudfront-continuous-deployment-weight-range", "ERROR", name, "Properties.ContinuousDeploymentPolicyConfig.TrafficConfig",
	sprintf("Weight %v is above the 0.15 maximum", [w]),
	_pf_cf_continuous_deployment_weight_range_fix, _pf_cf_continuous_deployment_weight_range_url) if {
	some name in resources_of_type("AWS::CloudFront::ContinuousDeploymentPolicy")
	tc := object.get(_pf_cflib_props(name, "ContinuousDeploymentPolicyConfig"), "TrafficConfig", null)
	is_object(tc)
	sw := object.get(tc, "SingleWeightConfig", null)
	is_object(sw)
	raw := object.get(sw, "Weight", "__pf_absent")
	raw != "__pf_absent"
	w := to_number(raw)
	w > 0.15
}
