package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-global-write-forwarding-requires-global", "ERROR", name,
	"Properties.EnableGlobalWriteForwarding",
	"EnableGlobalWriteForwarding is set without GlobalClusterIdentifier (\"Requested global functionality, but global cluster identifier is not specified\")",
	"Set GlobalClusterIdentifier, or drop the flag",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbcluster.html") if {
	some name in resources_of_type("AWS::RDS::DBCluster")
	_pf_rds_true(name, "EnableGlobalWriteForwarding")
	not _pf_rds_has(name, "GlobalClusterIdentifier")
}
