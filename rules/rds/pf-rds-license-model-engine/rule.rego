package cdk_preflight

import rego.v1

# 実測で確定しているエンジンだけ。挙がっていないエンジンは黙る（under-claim）。
_pf_rdslic := {
	"postgres": {"postgresql-license"},
	"mysql": {"general-public-license"},
	"mariadb": {"general-public-license"},
}

violation contains make_diag_full("pf-rds-license-model-engine", "ERROR", name,
	"Properties.LicenseModel",
	sprintf("LicenseModel %v is not valid for engine %v (\"Invalid license model 'bring-your-own-license' for engine 'postgres'. Valid license models are: postgresql-license\")", [lm, e]),
	"Use the license model the engine supports",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	e := _pf_rds_engine(name)
	allowed := _pf_rdslic[e]
	lm := resolve(name, "Properties.LicenseModel")
	is_string(lm)
	not lm in allowed
}
