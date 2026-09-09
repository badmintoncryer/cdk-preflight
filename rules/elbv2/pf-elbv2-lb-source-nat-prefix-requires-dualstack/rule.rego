package cdk_preflight

import rego.v1

_pf_elbsnd_fix := "Set IpAddressType to dualstack, or drop EnablePrefixForIpv6SourceNat"

_pf_elbsnd_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateLoadBalancer.html"

violation contains make_diag_full("pf-elbv2-lb-source-nat-prefix-requires-dualstack", "ERROR", name,
	"Properties.EnablePrefixForIpv6SourceNat",
	sprintf("EnablePrefixForIpv6SourceNat is 'on' with IpAddressType '%s'; CreateLoadBalancer fails with \"'EnablePrefixForIpv6SourceNat' can only be specified when using IpAddressType 'dualstack'.\"", [ipt]),
	_pf_elbsnd_fix, _pf_elbsnd_url) if {
	some name in _pf_elb_lbs
	_pf_elb_str(name, "EnablePrefixForIpv6SourceNat") == "on"
	ipt := object.get(_pf_elb_props(name), "IpAddressType", "ipv4")
	ipt != "dualstack"
}
