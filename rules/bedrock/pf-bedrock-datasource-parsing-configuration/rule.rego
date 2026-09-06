package cdk_preflight

import rego.v1

# The schema requires only ParsingStrategy; the foundation-model parser needs
# its ModelArn block (measured 2026-09-06).
violation contains make_diag_full("pf-bedrock-datasource-parsing-configuration", "ERROR", name,
	"Properties.VectorIngestionConfiguration.ParsingConfiguration.BedrockFoundationModelConfiguration",
	"ParsingStrategy is BEDROCK_FOUNDATION_MODEL but BedrockFoundationModelConfiguration is missing; CreateDataSource fails with \"Bedrock Foundation Model Configuration is required for this parsing strategy\"",
	"Add BedrockFoundationModelConfiguration.ModelArn (a Claude / Nova vision model of the deploy Region)",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_ParsingConfiguration.html") if {
	some name in resources_of_type("AWS::Bedrock::DataSource")
	pc := object.get(object.get(_pf_bedrocklib_props(name), "VectorIngestionConfiguration", {}), "ParsingConfiguration", null)
	is_object(pc)
	pc.ParsingStrategy == "BEDROCK_FOUNDATION_MODEL"
	not _pf_bedrocklib_has(pc, "BedrockFoundationModelConfiguration")
}
