package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-hostedzone-name-tld", "ERROR", name,
	"Properties.Name",
	sprintf("hosted zone name %s is a single label; Route 53 does not host top-level domains", [n]),
	"Use a domain you control, such as example.com",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DomainNameFormat.html") if {
	some name in resources_of_type("AWS::Route53::HostedZone")
	n := _pf_r53z_str(_pf_r53z_props(name), "Name")
	count(split(trim_suffix(n, "."), ".")) == 1
	n != ""
}
