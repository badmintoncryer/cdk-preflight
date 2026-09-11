package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-endpoint-ip-format", "ERROR", name,
	"Properties.IpAddresses",
	sprintf("IpAddresses contains Ip '%s', which is not a valid IPv4 address", [v]),
	"Use a dotted-quad IPv4 address inside the subnet CIDR",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53resolver-resolverendpoint.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverEndpoint")
	p := _pf_r53r_props(name)
	some ip in _pf_r53r_ips(p)
	v := _pf_r53r_str(ip, "Ip")
	not _pf_r53r_ipv4(v)
}
