package cdk_preflight

import rego.v1

_pf_cf_realtime_log_endpoint_stream_type_fix := "Set StreamType to Kinesis"

_pf_cf_realtime_log_endpoint_stream_type_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-realtimelogconfig.html"

violation contains make_diag_full("pf-cloudfront-realtime-log-endpoint-stream-type", "ERROR", name, sprintf("Properties.EndPoints.%d", [it.index]),
	sprintf("StreamType %v is not supported; only Kinesis is", [st]),
	_pf_cf_realtime_log_endpoint_stream_type_fix, _pf_cf_realtime_log_endpoint_stream_type_url) if {
	some name in resources_of_type("AWS::CloudFront::RealtimeLogConfig")
	some it in flatten_list(name, "Properties.EndPoints")
	st := object.get(it.value, "StreamType", null)
	is_string(st)
	st != "Kinesis"
}
