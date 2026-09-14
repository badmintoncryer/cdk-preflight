package cdk_preflight

import rego.v1

# Only one configuration property of a custom action type may be queryable.
violation contains make_diag_full("pf-codepipeline-cat-queryable-max-1", "ERROR", name,
	"Properties.ConfigurationProperties",
	sprintf("%d configuration properties are Queryable (%v); CreateCustomActionType fails with \"Multiple queryable configuration properties found with names '%v'. Up to one queryable property may be specified.\"", [count(q), concat(", ", sort(q)), concat(", ", sort(q))]),
	"Leave Queryable true on at most one configuration property",
	"https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_ActionConfigurationProperty.html") if {
	some name in resources_of_type("AWS::CodePipeline::CustomActionType")
	props := object.get(_pf_cplib_props(name), "ConfigurationProperties", [])
	q := {n | some p in props; _pf_cplib_plain(p); object.get(p, "Queryable", false) == true; n := object.get(p, "Name", "")}
	count(q) > 1
}
