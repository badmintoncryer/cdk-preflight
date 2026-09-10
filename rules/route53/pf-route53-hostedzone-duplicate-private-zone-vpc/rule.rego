package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-hostedzone-duplicate-private-zone-vpc", "ERROR", name,
	"Properties.VPCs",
	sprintf("hosted zone %s carries the same domain name and VPC as %s; Route 53 answers ConflictingDomainExists", [name, other]),
	"Associate the second private zone with a different VPC, or drop it",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/hosted-zone-private-considerations.html") if {
	some name in resources_of_type("AWS::Route53::HostedZone")
	some other in resources_of_type("AWS::Route53::HostedZone")
	name < other
	_pf_r53z_zname(name) == _pf_r53z_zname(other)
	count(_pf_r53z_vpcidset(name) & _pf_r53z_vpcidset(other)) > 0
}
