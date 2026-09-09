package cdk_preflight

import rego.v1

_pf_elbaalb_fix := "Set access_logs.s3.bucket to the bucket that carries the ELB log-delivery policy"

_pf_elbaalb_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_LoadBalancerAttribute.html"

violation contains make_diag_full("pf-elbv2-lb-attr-access-logs-bucket-required", "ERROR", name,
	sprintf("Properties.LoadBalancerAttributes.%d.Value", [p.index]),
	"access_logs.s3.enabled is 'true' with no access_logs.s3.bucket; ModifyLoadBalancerAttributes fails with \"The key 'access_logs.s3.bucket' must set in order to enable access logs\"",
	_pf_elbaalb_fix, _pf_elbaalb_url) if {
	some name in _pf_elb_lbs
	some p in _pf_elb_pairs(name, "LoadBalancerAttributes")
	p.key == "access_logs.s3.enabled"
	p.value == "true"
	not _pf_elb_attrhas(name, "LoadBalancerAttributes", "access_logs.s3.bucket")
}
