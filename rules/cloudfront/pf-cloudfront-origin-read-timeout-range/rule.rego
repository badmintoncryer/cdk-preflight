package cdk_preflight

import rego.v1

_pf_cf_origin_read_timeout_range_fix := "Set OriginReadTimeout to at least 1 second"

_pf_cf_origin_read_timeout_range_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-origin.html"

# 上限は見ない: 120 秒は引き上げ可能なクォータ（L-AECE9FA7 "Response timeout per origin"、
# Adjustable）で、引き上げたアカウントでは 121 が通る。テンプレートからはどちらの
# アカウントか分からないので、弾くと誤検出になる（原則 6）。下限 1 はクォータではない
# （2026-09-13 us-east-1 CreateDistribution: originReadTimeout 0 は
# InvalidOriginReadTimeout で拒否、120 は既定のクォータのまま作成できる）。
violation contains make_diag_full("pf-cloudfront-origin-read-timeout-range", "ERROR", name, o.path,
	sprintf("OriginReadTimeout %v is less than 1", [v]),
	_pf_cf_origin_read_timeout_range_fix, _pf_cf_origin_read_timeout_range_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some o in _pf_cflib_origins(name)
	oc := object.get(o.value, "CustomOriginConfig", null)
	is_object(oc)
	vraw := object.get(oc, "OriginReadTimeout", "__pf_absent")
	vraw != "__pf_absent"
	v := to_number(vraw)
	v < 1
}
