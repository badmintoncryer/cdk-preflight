package cdk_preflight

import rego.v1

# CreateKnowledgeBase pairs the auth Type with its credential field
# (measured 2026-09-06): USERNAME_PASSWORD needs UsernamePasswordSecretArn,
# USERNAME (provisioned) needs DatabaseUser, IAM accepts neither.
_pf_kbsa_url := "https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_RedshiftServerlessAuthConfiguration.html"
_pf_kbsa_base := "Properties.KnowledgeBaseConfiguration.SqlKnowledgeBaseConfiguration.RedshiftConfiguration.QueryEngineConfiguration"

_pf_kbsa_auth(name) := [kind, a] if {
	p := _pf_bedrocklib_props(name)
	qe := object.get(object.get(object.get(object.get(p, "KnowledgeBaseConfiguration", {}), "SqlKnowledgeBaseConfiguration", {}), "RedshiftConfiguration", {}), "QueryEngineConfiguration", {})
	some kind in ["ServerlessConfiguration", "ProvisionedConfiguration"]
	a := object.get(object.get(qe, kind, {}), "AuthConfiguration", null)
	is_object(a)
}

_pf_kbsa_needs := {"USERNAME_PASSWORD": "UsernamePasswordSecretArn", "USERNAME": "DatabaseUser"}

violation contains make_diag_full("pf-bedrock-kb-sql-auth-configuration", "ERROR", name,
	sprintf("%s.%s.AuthConfiguration.%s", [_pf_kbsa_base, k[0], need]),
	sprintf("AuthConfiguration.Type %s needs %s; CreateKnowledgeBase fails with \"%s auth type must provide %s%s\"", [t, need, t, lower(substring(need, 0, 1)), substring(need, 1, -1)]),
	sprintf("Set AuthConfiguration.%s", [need]),
	_pf_kbsa_url) if {
	some name in resources_of_type("AWS::Bedrock::KnowledgeBase")
	k := _pf_kbsa_auth(name)
	t := k[1].Type
	need := _pf_kbsa_needs[t]
	not _pf_bedrocklib_has(k[1], need)
}

violation contains make_diag_full("pf-bedrock-kb-sql-auth-configuration", "ERROR", name,
	sprintf("%s.%s.AuthConfiguration.%s", [_pf_kbsa_base, k[0], extra]),
	sprintf("AuthConfiguration.Type IAM carries %s; CreateKnowledgeBase fails with \"IAM auth type must provide no additional properties\"", [extra]),
	"Remove the credential field, or change Type to USERNAME_PASSWORD / USERNAME",
	_pf_kbsa_url) if {
	some name in resources_of_type("AWS::Bedrock::KnowledgeBase")
	k := _pf_kbsa_auth(name)
	k[1].Type == "IAM"
	some extra in ["UsernamePasswordSecretArn", "DatabaseUser"]
	_pf_bedrocklib_has(k[1], extra)
}
