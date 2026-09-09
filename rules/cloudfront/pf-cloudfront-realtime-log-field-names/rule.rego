package cdk_preflight

import rego.v1

_pf_cf_realtime_log_field_names_fix := "Use one of the documented real-time log field names"

_pf_cf_realtime_log_field_names_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-realtimelogconfig.html"

_pf_cf_realtime_log_field_names_known := {
	"asn",
	"c-country",
	"c-ip",
	"c-ip-version",
	"c-port",
	"cache-behavior-path-pattern",
	"cmcd-buffer-length",
	"cmcd-buffer-starvation",
	"cmcd-content-id",
	"cmcd-deadline",
	"cmcd-encoded-bitrate",
	"cmcd-measured-throughput",
	"cmcd-next-object-request",
	"cmcd-next-range-request",
	"cmcd-object-duration",
	"cmcd-object-type",
	"cmcd-playback-rate",
	"cmcd-requested-maximum-throughput",
	"cmcd-session-id",
	"cmcd-startup",
	"cmcd-stream-type",
	"cmcd-streaming-format",
	"cmcd-top-bitrate",
	"cmcd-version",
	"connection-id",
	"cs-accept",
	"cs-accept-encoding",
	"cs-bytes",
	"cs-cookie",
	"cs-header-names",
	"cs-headers",
	"cs-headers-count",
	"cs-host",
	"cs-method",
	"cs-protocol",
	"cs-protocol-version",
	"cs-referer",
	"cs-uri-query",
	"cs-uri-stem",
	"cs-user-agent",
	"distribution-tenant-id",
	"fle-encrypted-fields",
	"fle-status",
	"origin-fbl",
	"origin-lbl",
	"primary-distribution-dns-name",
	"primary-distribution-id",
	"r-host",
	"s-ip",
	"sc-bytes",
	"sc-content-len",
	"sc-content-type",
	"sc-range-end",
	"sc-range-start",
	"sc-status",
	"sr-reason",
	"ssl-cipher",
	"ssl-protocol",
	"time-taken",
	"time-to-first-byte",
	"timestamp",
	"viewer-request-log-data",
	"viewer-response-log-data",
	"x-edge-detailed-result-type",
	"x-edge-location",
	"x-edge-mqcs",
	"x-edge-request-id",
	"x-edge-response-result-type",
	"x-edge-result-type",
	"x-forwarded-for",
	"x-host-header",
}

violation contains make_diag_full("pf-cloudfront-realtime-log-field-names", "ERROR", name, "Properties.Fields",
	sprintf("%v is not a CloudFront real-time log field", [f]),
	_pf_cf_realtime_log_field_names_fix, _pf_cf_realtime_log_field_names_url) if {
	some name in resources_of_type("AWS::CloudFront::RealtimeLogConfig")
	some it in flatten_list(name, "Properties.Fields")
	f := it.value
	is_string(f)
	not f in _pf_cf_realtime_log_field_names_known
}
