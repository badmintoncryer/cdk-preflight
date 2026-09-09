package cdk_preflight

import rego.v1

_pf_elbsnn_fix := "Drop EnablePrefixForIpv6SourceNat, or make this a network load balancer"

_pf_elbsnn_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateLoadBalancer.html"

violation contains make_diag_full("pf-elbv2-lb-source-nat-prefix-nlb-only", "ERROR", name,
	"Properties.EnablePrefixForIpv6SourceNat",
	sprintf("EnablePrefixForIpv6SourceNat is set on a %s load balancer; CreateLoadBalancer fails with \"'EnablePrefixForIpv6SourceNat' can only be specified for LoadBalancer type 'network'.\"", [t]),
	_pf_elbsnn_fix, _pf_elbsnn_url) if {
	some name in _pf_elb_lbs
	t := _pf_elb_lbtype(name)
	t != "network"
	_pf_elb_has(name, "EnablePrefixForIpv6SourceNat")
}
