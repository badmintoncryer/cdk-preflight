package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-limitless-delete-automated-backups", "ERROR", name,
	"Properties.DeleteAutomatedBackups",
	"DeleteAutomatedBackups: false is not allowed on a ClusterScalabilityType: limitless cluster",
	"Drop DeleteAutomatedBackups for a Limitless cluster",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbcluster.html") if {
	some name in resources_of_type("AWS::RDS::DBCluster")
	resolve(name, "Properties.ClusterScalabilityType") == "limitless"
	_pf_rds_false(name, "DeleteAutomatedBackups")
}
