package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53profiles-profileresourceassociation-resourcearn-type", "ERROR", name,
	"Properties.ResourceArn",
	sprintf("ResourceArn is a %s ARN; a Profile only takes a private hosted zone, a DNS Firewall rule group, a Resolver rule or an interface VPC endpoint", [k]),
	"Point ResourceArn at one of the four supported resource types",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53profiles_AssociateResourceToProfile.html") if {
	some name in resources_of_type("AWS::Route53Profiles::ProfileResourceAssociation")
	k := _pf_r53r_arn_kind(_pf_r53r_str(_pf_r53r_props(name), "ResourceArn"))
	not k in {"route53:hostedzone", "route53resolver:firewall-rule-group", "route53resolver:resolver-rule", "ec2:vpc-endpoint"}
}
