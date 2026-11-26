package cdk_preflight

import rego.v1

_pf_rdsx_on(name) if coerce_to_bool(resolve(name, "Properties.WithExpressConfiguration")) == true

violation contains make_diag_full("pf-rds-cluster-express-postgresql-only", "ERROR", name,
	"Properties.Engine",
	sprintf("WithExpressConfiguration with engine %v; the create fails with \"Amazon RDS can't enable Internet Access Gateway because this feature isn't available in your account for the specified Region or engine\"", [eng]),
	"Use Engine aurora-postgresql, or drop WithExpressConfiguration",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbcluster.html") if {
	some name in resources_of_type("AWS::RDS::DBCluster")
	_pf_rdsx_on(name)
	eng := resolve(name, "Properties.Engine")
	is_string(eng)
	not input.resources[eng]
	lower(eng) != "aurora-postgresql"
}
