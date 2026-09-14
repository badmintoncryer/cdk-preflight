package cdk_preflight

import rego.v1

# A queryable configuration property is polled by the job worker, so it must be
# required and must not be a secret. One service check covers both halves.
violation contains make_diag_full("pf-codepipeline-cat-queryable-not-secret", "ERROR", name,
	sprintf("Properties.ConfigurationProperties.%v", [i]),
	sprintf("configuration property '%v' is Queryable with Secret %v and Required %v; CreateCustomActionType fails with \"Invalid queryable property '%v'. Queryable configuration properties must be required and non-secret.\"", [pn, secret, required, pn]),
	"Set Secret to false and Required to true on the queryable property",
	"https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_ActionConfigurationProperty.html") if {
	some name in resources_of_type("AWS::CodePipeline::CustomActionType")
	some i, p in object.get(_pf_cplib_props(name), "ConfigurationProperties", [])
	_pf_cplib_plain(p)
	object.get(p, "Queryable", false) == true
	secret := object.get(p, "Secret", false)
	required := object.get(p, "Required", false)
	not _pf_cplib_queryable_ok(secret, required)
	pn := object.get(p, "Name", "")
}
