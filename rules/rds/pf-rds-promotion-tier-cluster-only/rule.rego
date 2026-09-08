package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-promotion-tier-cluster-only", "ERROR", name,
	"Properties.PromotionTier",
	"PromotionTier is set on an instance without DBClusterIdentifier (\"You cannot set the promotion tier for a DB instance that is not part of an DB Cluster.\")",
	"Drop PromotionTier, or attach the instance to a cluster",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	_pf_rds_has(name, "PromotionTier")
	not _pf_rds_has(name, "DBClusterIdentifier")
}
