package cdk_preflight

import rego.v1

_pf_r53_pzhc_msg := "A record with no routing policy cannot reference a health check; Route 53 answers \"DNS name must have alternate ResourceRecordSet responses configured via a routing policy\""

_pf_r53_pzhc_fix := "Give the record a routing policy, or drop HealthCheckId"

_pf_r53_pzhc_url := "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html"

# 2026-09-08 の調査時は private zone の記述から起こしたルールだったが、実機は
# public zone でも同じ理由で弾く（simple routing にはヘルスチェックを付けられない）。
# ゾーンの種別を問わずに鳴らす。
violation contains make_diag_full("pf-route53-private-zone-health-check-policy", "ERROR", name,
	"Properties.HealthCheckId",
	_pf_r53_pzhc_msg, _pf_r53_pzhc_fix, _pf_r53_pzhc_url) if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	_pf_r53lib_has(rs, "HealthCheckId")
	count(_pf_r53lib_kinds(rs)) == 0
}

violation contains make_diag_full("pf-route53-private-zone-health-check-policy", "ERROR", name,
	sprintf("Properties.RecordSets[%d].HealthCheckId", [_pf_it.index]),
	_pf_r53_pzhc_msg, _pf_r53_pzhc_fix, _pf_r53_pzhc_url) if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	_pf_r53lib_has(rs, "HealthCheckId")
	count(_pf_r53lib_kinds(rs)) == 0
}
