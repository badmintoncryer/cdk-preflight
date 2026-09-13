package cdk_preflight

import rego.v1

# Route 53 normalises the trailing dot away before it measures the name, so the
# limit bites at 253 characters of labels and separators, not the 255 the docs
# quote (bench 2026-09-13 us-east-1: 253 creates, 254 answers DomainNameTooLong,
# with or without the trailing dot).
violation contains make_diag_full("pf-route53-hostedzone-name-total-253", "ERROR", name,
	"Properties.Name",
	sprintf("the hosted zone name is %d characters; a DNS name stops at 253 once the trailing dot is dropped (the CloudFormation reference says 1024)", [count(trim_suffix(n, "."))]),
	"Shorten the domain name to 253 characters or fewer",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DomainNameFormat.html") if {
	some name in resources_of_type("AWS::Route53::HostedZone")
	n := _pf_r53z_str(_pf_r53z_props(name), "Name")
	count(trim_suffix(n, ".")) > 253
}
