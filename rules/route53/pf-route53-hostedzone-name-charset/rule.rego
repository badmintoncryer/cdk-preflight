package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-hostedzone-name-charset", "ERROR", name,
	"Properties.Name",
	sprintf("hosted zone name %s contains a space or control character; Route 53 wants printable ASCII, with 3-digit octal escapes for anything else", [n]),
	"Remove the space, or write the character as a 3-digit octal escape such as \\\\040",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DomainNameFormat.html") if {
	some name in resources_of_type("AWS::Route53::HostedZone")
	n := _pf_r53z_str(_pf_r53z_props(name), "Name")
	regex.match(`[\x00-\x20\x7f]`, n)
}
