package cdk_preflight

import rego.v1

# CreateDataSource resolves the parser model in its own Region only (measured
# 2026-09-06). Needs data.cdk_preflight.deploy_region.
violation contains make_diag_full("pf-bedrock-datasource-parsing-model-region", "ERROR", name,
	"Properties.VectorIngestionConfiguration.ParsingConfiguration.BedrockFoundationModelConfiguration.ModelArn",
	sprintf("Parsing model '%s' cannot be served from Region '%s'; CreateDataSource fails with \"Provided Bedrock Foundation Model is in a different region\" / \"inference profile … does not exist\"", [_pf_bedrocklib_model_id(arn), region]),
	"Reference the model ARN of the deploy Region, or a cross-Region profile of its geography",
	"https://docs.aws.amazon.com/bedrock/latest/userguide/knowledge-base-supported.html") if {
	some name in resources_of_type("AWS::Bedrock::DataSource")
	region := _pf_bedrocklib_region
	arn := resolve(name, "Properties.VectorIngestionConfiguration.ParsingConfiguration.BedrockFoundationModelConfiguration.ModelArn")
	_pf_bedrocklib_model_region_mismatch(arn, region)
}
