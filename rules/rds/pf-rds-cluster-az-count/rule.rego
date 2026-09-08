package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-cluster-az-count", "ERROR", name,
	"Properties.AvailabilityZones",
	sprintf("AvailabilityZones lists %v zones (\"You cannot specify more than 3 availability zones.\")", [count(azs)]),
	"List at most 3 availability zones",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbcluster.html") if {
	some name in resources_of_type("AWS::RDS::DBCluster")
	azs := flatten_list(name, "Properties.AvailabilityZones")
	count(azs) > 3
}
