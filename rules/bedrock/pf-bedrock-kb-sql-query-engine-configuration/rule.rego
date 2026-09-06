package cdk_preflight

import rego.v1

# The schema requires only Type; CreateKnowledgeBase requires ServerlessConfiguration
# for SERVERLESS and ProvisionedConfiguration for PROVISIONED (measured 2026-09-06).
_pf_kbqe_member := {"SERVERLESS": "ServerlessConfiguration", "PROVISIONED": "ProvisionedConfiguration"}
_pf_kbqe_path := "Properties.KnowledgeBaseConfiguration.SqlKnowledgeBaseConfiguration.RedshiftConfiguration.QueryEngineConfiguration"

violation contains make_diag_full("pf-bedrock-kb-sql-query-engine-configuration", "ERROR", name,
	sprintf("%s.%s", [_pf_kbqe_path, m]),
	sprintf("QueryEngineConfiguration.Type is %s but %s is missing; CreateKnowledgeBase fails with \"query engine type REDSHIFT with %s type must provide %s%s\"", [t, m, t, lower(substring(m, 0, 1)), substring(m, 1, -1)]),
	sprintf("Add QueryEngineConfiguration.%s, or change Type", [m]),
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_RedshiftQueryEngineConfiguration.html") if {
	some name in resources_of_type("AWS::Bedrock::KnowledgeBase")
	p := _pf_bedrocklib_props(name)
	qe := object.get(object.get(object.get(object.get(p, "KnowledgeBaseConfiguration", {}), "SqlKnowledgeBaseConfiguration", {}), "RedshiftConfiguration", {}), "QueryEngineConfiguration", null)
	is_object(qe)
	t := qe.Type
	m := _pf_kbqe_member[t]
	not _pf_bedrocklib_has(qe, m)
}
