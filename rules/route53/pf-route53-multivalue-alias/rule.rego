package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-multivalue-alias", "ERROR", name,
	"Properties.MultiValueAnswer",
	"MultiValueAnswer cannot be combined with AliasTarget; the service rejects it with \"Multivalue answer rrset should not be an alias rrset\"",
	"Use plain multivalue records with ResourceRecords, or drop MultiValueAnswer and keep the alias",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-recordset.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	resolve(name, "Properties.MultiValueAnswer") == true
	is_object(resolve(name, "Properties.AliasTarget"))
}
