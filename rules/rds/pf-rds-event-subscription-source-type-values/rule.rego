package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-event-subscription-source-type-values", "ERROR", name,
	"Properties.SourceType",
	sprintf("SourceType %v is not an RDS event source type (\"Invalid event source type. Valid types are 'db-instance', 'db-security-group', 'db-parameter-group', 'db-snapshot', 'db-cluster', 'db-cluster-snapshot' ...\")", [st]),
	"Use one of the documented source types",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-eventsubscription.html") if {
	some name in resources_of_type("AWS::RDS::EventSubscription")
	st := resolve(name, "Properties.SourceType")
	is_string(st)
	not input.resources[st]
	not st in {"db-instance", "db-security-group", "db-parameter-group", "db-snapshot", "db-cluster", "db-cluster-snapshot", "db-proxy", "custom-engine-version", "blue-green-deployment"}
}
