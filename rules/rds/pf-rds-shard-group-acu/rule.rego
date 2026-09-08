package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-shard-group-acu", "ERROR", name,
	"Properties.MaxACU",
	sprintf("MaxACU %v is below MinACU %v", [mx, mn]),
	"Raise MaxACU to at least MinACU",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbshardgroup.html") if {
	some name in resources_of_type("AWS::RDS::DBShardGroup")
	mx := to_number(resolve(name, "Properties.MaxACU"))
	mn := to_number(resolve(name, "Properties.MinACU"))
	mx < mn
}
