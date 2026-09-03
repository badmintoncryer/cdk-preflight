package cdk_preflight

import rego.v1

_pf_rdspw_url := "https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBInstance.html"

_pf_rdspw_types := {"AWS::RDS::DBInstance", "AWS::RDS::DBCluster"}

_pf_rdspw_forbidden := {"/", "@", "\"", " "}

violation contains make_diag_full("pf-rds-password-valid", "ERROR", name,
	"Properties.MasterUserPassword",
	"MasterUserPassword is shorter than 8 characters; RDS rejects it at create time",
	"Use 8+ characters, or a Secrets Manager reference",
	_pf_rdspw_url) if {
	some rtype in _pf_rdspw_types
	some name in resources_of_type(rtype)
	pw := resolve(name, "Properties.MasterUserPassword")
	is_string(pw)
	count(pw) < 8
}

violation contains make_diag_full("pf-rds-password-valid", "ERROR", name,
	"Properties.MasterUserPassword",
	sprintf("MasterUserPassword contains '%s'; RDS forbids '/', '@', double quotes and spaces", [ch]),
	"Remove the forbidden character, or use a Secrets Manager reference",
	_pf_rdspw_url) if {
	some rtype in _pf_rdspw_types
	some name in resources_of_type(rtype)
	pw := resolve(name, "Properties.MasterUserPassword")
	is_string(pw)
	some ch in _pf_rdspw_forbidden
	contains(pw, ch)
}
