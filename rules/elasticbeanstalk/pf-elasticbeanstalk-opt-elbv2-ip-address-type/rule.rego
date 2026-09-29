package cdk_preflight

import rego.v1

_pf_eb_opt_elbv2_ip_address_type_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html"

violation contains make_diag_full("pf-elasticbeanstalk-opt-elbv2-ip-address-type", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	"IpAddressType is set but the environment uses a Classic Load Balancer (the default when LoadBalancerType is not set); only Application and Network Load Balancers take it",
	"Set LoadBalancerType to application or network, or remove IpAddressType", _pf_eb_opt_elbv2_ip_address_type_url) if {
	o := _pf_eblib_opt[_]
	o.k == "aws:elbv2:loadbalancer|IpAddressType"
	_pf_eblib_clean(o.rn)
	_pf_eblib_lbtype(o.rn) == "classic"
	not _pf_eblib_shared(o.rn)
}
