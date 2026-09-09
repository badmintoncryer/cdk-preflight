package cdk_preflight

import rego.v1

_pf_cf_rhp_server_timing_sampling_rate_required_fix := "Set SamplingRate (0-100) alongside Enabled: true"

_pf_cf_rhp_server_timing_sampling_rate_required_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-responseheaderspolicy.html"

violation contains make_diag_full("pf-cloudfront-rhp-server-timing-sampling-rate-required", "ERROR", name, "Properties.ResponseHeadersPolicyConfig.ServerTimingHeadersConfig",
	"ServerTimingHeadersConfig is enabled but SamplingRate is not set",
	_pf_cf_rhp_server_timing_sampling_rate_required_fix, _pf_cf_rhp_server_timing_sampling_rate_required_url) if {
	some name in resources_of_type("AWS::CloudFront::ResponseHeadersPolicy")
	cfgv := _pf_cflib_props(name, "ResponseHeadersPolicyConfig")
	st := object.get(cfgv, "ServerTimingHeadersConfig", null)
	is_object(st)
	object.get(st, "Enabled", false) == true
	object.get(st, "SamplingRate", "__pf_absent") == "__pf_absent"
}
