package cdk_preflight

import rego.v1

_pf_elbtip_fix := "Register an address from the VPC CIDR, RFC 1918 or RFC 6598 space"

_pf_elbtip_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateTargetGroup.html"

_pf_elbtip_private := ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"]

_pf_elbtip_ok(ip) if {
	some cidr in _pf_elbtip_private
	_pf_ec2lib_cidr_has_ip(cidr, ip)
}

violation contains make_diag_full("pf-elbv2-tg-target-ip-not-public", "ERROR", name,
	sprintf("Properties.Targets.%d.Id", [t.index]),
	sprintf("Target '%s' is a publicly routable address; RegisterTargets only accepts addresses from the VPC CIDR, RFC 1918 or RFC 6598 space", [ip]),
	_pf_elbtip_fix, _pf_elbtip_url) if {
	some name in _pf_elb_tgs
	_pf_elb_tgtype(name) == "ip"
	some t in flatten_list(name, "Properties.Targets")
	ip := _pf_elb_oget(t.value, "Id")
	_pf_elb_lit(ip)
	regex.match(`^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$`, ip)
	not _pf_elbtip_ok(ip)
}
