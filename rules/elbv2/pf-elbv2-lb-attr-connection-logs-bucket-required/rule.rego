package cdk_preflight

import rego.v1

_pf_elbaclb_fix := "Set connection_logs.s3.bucket to the bucket that carries the ELB log-delivery policy"

_pf_elbaclb_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_LoadBalancerAttribute.html"

violation contains make_diag_full("pf-elbv2-lb-attr-connection-logs-bucket-required", "ERROR", name,
	sprintf("Properties.LoadBalancerAttributes.%d.Value", [p.index]),
	"connection_logs.s3.enabled is 'true' with no connection_logs.s3.bucket; ModifyLoadBalancerAttributes fails with \"The key 'connection_logs.s3.bucket' must set in order to enable connection logs\"",
	_pf_elbaclb_fix, _pf_elbaclb_url) if {
	some name in _pf_elb_lbs
	some p in _pf_elb_pairs(name, "LoadBalancerAttributes")
	p.key == "connection_logs.s3.enabled"
	p.value == "true"
	not _pf_elb_attrhas(name, "LoadBalancerAttributes", "connection_logs.s3.bucket")
}
