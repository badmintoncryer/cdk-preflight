package cdk_preflight

import rego.v1

_pf_ecrrct_url := "https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_CreateRepositoryCreationTemplate.html"

_pf_ecrrct_fix := "List only REPLICATION, PULL_THROUGH_CACHE or CREATE_ON_PUSH in AppliedFor"

# The registry schema types AppliedFor as a plain string list, so neither the
# schema nor cfn-lint sees the enum.
_pf_ecrrct_values := {"REPLICATION", "PULL_THROUGH_CACHE", "CREATE_ON_PUSH"}

violation contains make_diag_full("pf-ecr-repository-creation-template-applied-for", "ERROR", name,
	sprintf("Properties.AppliedFor[%d]", [i]),
	sprintf("'%s' is not an accepted AppliedFor value; CreateRepositoryCreationTemplate fails with \"Member must satisfy enum value set: [REPLICATION, PULL_THROUGH_CACHE, CREATE_ON_PUSH]\"", [v]),
	_pf_ecrrct_fix, _pf_ecrrct_url) if {
	some name in resources_of_type("AWS::ECR::RepositoryCreationTemplate")
	applied := resolve(name, "Properties.AppliedFor")
	is_array(applied)
	some i, v in applied
	is_string(v)
	not input.resources[v]
	not v in _pf_ecrrct_values
}
