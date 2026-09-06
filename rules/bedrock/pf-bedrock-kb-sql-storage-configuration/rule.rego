package cdk_preflight

import rego.v1

# The schema requires only Type per storage entry; CreateKnowledgeBase needs the
# matching block (RedshiftConfiguration for REDSHIFT, AwsDataCatalogConfiguration
# for AWS_DATA_CATALOG — "must specify exactly one storage configuration",
# measured 2026-09-06).
_pf_kbss_member := {"REDSHIFT": "RedshiftConfiguration", "AWS_DATA_CATALOG": "AwsDataCatalogConfiguration"}

violation contains make_diag_full("pf-bedrock-kb-sql-storage-configuration", "ERROR", name,
	sprintf("Properties.KnowledgeBaseConfiguration.SqlKnowledgeBaseConfiguration.RedshiftConfiguration.StorageConfigurations[%d].%s", [i, m]),
	sprintf("Storage configuration Type %s has no %s; CreateKnowledgeBase fails with \"query engine type REDSHIFT must specify exactly one storage configuration\"", [t, m]),
	sprintf("Add %s to the storage configuration entry", [m]),
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_RedshiftQueryEngineStorageConfiguration.html") if {
	some name in resources_of_type("AWS::Bedrock::KnowledgeBase")
	p := _pf_bedrocklib_props(name)
	scs := object.get(object.get(object.get(object.get(p, "KnowledgeBaseConfiguration", {}), "SqlKnowledgeBaseConfiguration", {}), "RedshiftConfiguration", {}), "StorageConfigurations", [])
	some i, sc in scs
	is_object(sc)
	t := sc.Type
	m := _pf_kbss_member[t]
	not _pf_bedrocklib_has(sc, m)
}
