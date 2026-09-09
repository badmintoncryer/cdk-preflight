package cdk_preflight

import rego.v1

_pf_cf_continuous_deployment_session_ttl_order_fix := "Set IdleTTL to at most MaximumTTL"

_pf_cf_continuous_deployment_session_ttl_order_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-continuousdeploymentpolicy.html"

violation contains make_diag_full("pf-cloudfront-continuous-deployment-session-ttl-order", "ERROR", name, "Properties.ContinuousDeploymentPolicyConfig.TrafficConfig",
	sprintf("IdleTTL (%v) is greater than MaximumTTL (%v)", [i, m]),
	_pf_cf_continuous_deployment_session_ttl_order_fix, _pf_cf_continuous_deployment_session_ttl_order_url) if {
	some name in resources_of_type("AWS::CloudFront::ContinuousDeploymentPolicy")
	tc := object.get(_pf_cflib_props(name, "ContinuousDeploymentPolicyConfig"), "TrafficConfig", null)
	is_object(tc)
	sw := object.get(tc, "SingleWeightConfig", null)
	is_object(sw)
	ss := object.get(sw, "SessionStickinessConfig", null)
	is_object(ss)
	i := to_number(object.get(ss, "IdleTTL", null))
	m := to_number(object.get(ss, "MaximumTTL", null))
	i > m
}
