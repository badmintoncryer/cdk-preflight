package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-rule-targetip-ip-format", "ERROR", name,
	"Properties.TargetIps",
	sprintf("TargetIps contains Ip '%s', which is not a valid IPv4 address", [v]),
	"Use a dotted-quad IPv4 address",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-route53resolver-resolverrule-targetaddress.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverRule")
	p := _pf_r53r_props(name)
	some t in _pf_r53r_arr(p, "TargetIps")
	v := _pf_r53r_str(t, "Ip")
	not _pf_r53r_ipv4(v)
}
