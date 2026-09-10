package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-hostedzone-name-required", "ERROR", name,
	"Properties",
	"the hosted zone has no Name; CreateHostedZone requires one even though the CloudFormation schema does not",
	"Give the hosted zone its domain name",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-hostedzone.html") if {
	some name in resources_of_type("AWS::Route53::HostedZone")
	not _pf_r53z_has(_pf_r53z_props(name), "Name")
}
