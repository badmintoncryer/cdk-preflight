package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-hostedzone-name-punycode", "ERROR", name,
	"Properties.Name",
	sprintf("hosted zone name %s contains non-ASCII characters; Route 53 stores names in Punycode", [n]),
	"Convert the name to Punycode (xn--...) before putting it in the template",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DomainNameFormat.html") if {
	some name in resources_of_type("AWS::Route53::HostedZone")
	n := _pf_r53z_str(_pf_r53z_props(name), "Name")
	regex.match(`[^\x00-\x7f]`, n)
}
