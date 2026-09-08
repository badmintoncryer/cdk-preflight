package cdk_preflight

import rego.v1

_pf_rdsescat := {
	"db-cluster": {"configuration change", "creation", "deletion", "failover", "failure", "global-failover", "maintenance", "notification", "serverless"},
	"db-instance": {"availability", "backup", "configuration change", "creation", "deletion", "failover", "failure", "low storage", "maintenance", "notification", "read replica", "recovery", "restoration", "security patching"},
}

violation contains make_diag_full("pf-rds-event-subscription-categories", "ERROR", name,
	"Properties.EventCategories",
	sprintf("Event category %v does not exist for source type %v (\"Category : restoration not found for source type db-cluster.\")", [c, st]),
	"Use a category that the source type publishes",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-eventsubscription.html") if {
	some name in resources_of_type("AWS::RDS::EventSubscription")
	st := resolve(name, "Properties.SourceType")
	allowed := _pf_rdsescat[st]
	some it in flatten_list(name, "Properties.EventCategories")
	c := it.value
	is_string(c)
	not c in allowed
}
