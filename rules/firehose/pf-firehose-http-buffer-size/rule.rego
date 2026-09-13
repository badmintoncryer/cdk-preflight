package cdk_preflight

import rego.v1

# 下側は見ない: スキーマの minimum が 1 なので 0 以下は同梱エンジンが F3034 で止める
# （原則 1）。maximum は入っていないので 65 以上だけがここまで届く
# （2026-09-13 us-east-1: SizeInMBs 0 は BLOCK F3034/FATAL、65 は素通りして
# CreateDeliveryStream が ValidationException で拒否）。
violation contains make_diag_full("pf-firehose-http-buffer-size", "ERROR", name,
	"Properties.HttpEndpointDestinationConfiguration.BufferingHints.SizeInMBs",
	sprintf("SizeInMBs is %v; the stream create fails with \"failed to satisfy constraint: Member must have value less than or equal to 64\"", [v]),
	"Set SizeInMBs between 1 and 64 for an HTTP endpoint destination",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_HttpEndpointBufferingHints.html") if {
	some [name, path, c] in _pf_fhlib_dests
	path == "Properties.HttpEndpointDestinationConfiguration"
	raw := object.get(object.get(c, "BufferingHints", {}), "SizeInMBs", null)
	raw != null
	v := to_number(raw)
	v > 64
}
