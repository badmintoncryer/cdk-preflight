package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-cluster-express-default-port", "ERROR", name,
	"Properties.Port",
	sprintf("Port %v on an express cluster; the create fails with \"Amazon RDS requires a default port value of 5432 for DB engine aurora-postgresql when Internet Access Gateway is enabled\"", [p]),
	"Drop Port or set it to 5432, or drop WithExpressConfiguration",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbcluster.html") if {
	some name in resources_of_type("AWS::RDS::DBCluster")
	coerce_to_bool(resolve(name, "Properties.WithExpressConfiguration")) == true
	eng := resolve(name, "Properties.Engine")
	is_string(eng)
	lower(eng) == "aurora-postgresql"
	p := _pf_num(name, "Properties.Port")
	p != 5432
}
