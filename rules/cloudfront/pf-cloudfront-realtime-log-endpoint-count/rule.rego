package cdk_preflight

import rego.v1

_pf_cf_realtime_log_endpoint_count_fix := "Declare a single Kinesis endpoint"

_pf_cf_realtime_log_endpoint_count_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-realtimelogconfig.html"

violation contains make_diag_full("pf-cloudfront-realtime-log-endpoint-count", "ERROR", name, "Properties.EndPoints",
	sprintf("%v endpoints are declared; CloudFront accepts exactly one", [count(eps)]),
	_pf_cf_realtime_log_endpoint_count_fix, _pf_cf_realtime_log_endpoint_count_url) if {
	some name in resources_of_type("AWS::CloudFront::RealtimeLogConfig")
	eps := [e | some e in flatten_list(name, "Properties.EndPoints")]
	count(eps) > 1
}
