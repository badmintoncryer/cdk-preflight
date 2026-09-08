package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-cluster-storage-type", "ERROR", name,
	"Properties.StorageType",
	sprintf("StorageType %v is not valid for engine %v (\"You can't use the gp3 storage type.\")", [st, e]),
	"Use aurora or aurora-iopt1",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbcluster.html") if {
	some name in resources_of_type("AWS::RDS::DBCluster")
	e := _pf_rds_engine(name)
	_pf_rds_engine_in(name, {"aurora-mysql", "aurora-postgresql"})
	st := resolve(name, "Properties.StorageType")
	is_string(st)
	not st in {"aurora", "aurora-iopt1"}
}
