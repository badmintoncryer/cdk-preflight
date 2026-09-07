package cdk_preflight

import rego.v1

# RedshiftDataParameters takes one statement form and one credential form.
# Measured 2026-09-07, events:PutTargets, us-east-1: Sql together with Sqls
# gives "Either RedshiftDataParameters.sql or RedshiftDataParameters.sqls",
# and DbUser together with SecretManagerArn gives the matching message.
_pf_evrs_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-redshiftdataparameters.html"

_pf_evrs_params(name) := [t |
	some t in flatten_list(name, "Properties.Targets")
	is_object(t.value)
	is_object(object.get(t.value, "RedshiftDataParameters", null))
]

_pf_evrs_both(p, a, b) if {
	object.get(p, a, "__pf_absent") != "__pf_absent"
	object.get(p, b, "__pf_absent") != "__pf_absent"
}

violation contains make_diag_full("pf-events-target-redshift-parameters", "ERROR", name,
	sprintf("Properties.Targets.%d.RedshiftDataParameters", [t.index]),
	"Sql and Sqls are alternatives; PutTargets fails with \"Either RedshiftDataParameters.sql or RedshiftDataParameters.sqls\"",
	"Keep either Sql or Sqls",
	_pf_evrs_url) if {
	some name in resources_of_type("AWS::Events::Rule")
	some t in _pf_evrs_params(name)
	_pf_evrs_both(t.value.RedshiftDataParameters, "Sql", "Sqls")
}

violation contains make_diag_full("pf-events-target-redshift-parameters", "ERROR", name,
	sprintf("Properties.Targets.%d.RedshiftDataParameters", [t.index]),
	"DbUser and SecretManagerArn are alternatives; PutTargets fails with \"Either RedshiftDataParameters.dBUser or RedshiftDataParameters.secretManagerArn\"",
	"Keep either DbUser or SecretManagerArn",
	_pf_evrs_url) if {
	some name in resources_of_type("AWS::Events::Rule")
	some t in _pf_evrs_params(name)
	_pf_evrs_both(t.value.RedshiftDataParameters, "DbUser", "SecretManagerArn")
}
