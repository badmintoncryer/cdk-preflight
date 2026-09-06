package cdk_preflight

import rego.v1

# CreateDataSource refuses the intermediate bucket being the data bucket
# (measured 2026-09-06). Buckets are compared as literal names or as the same
# in-template bucket (Ref / GetAtt / ${Bucket} in a Fn::Sub).
_pf_dstb_bucket(v) := b if {
	b := _pf_bedrocklib_bucket_expr(v)
}

_pf_dstb_bucket(v) := b if {
	is_object(v)
	ref := object.get(v, "__ref", null)
	is_string(ref)
	b := sprintf("${%s}", [ref])
}

_pf_dstb_norm(b) := replace(b, ".Arn}", "}")

violation contains make_diag_full("pf-bedrock-datasource-transformation-bucket", "ERROR", name,
	"Properties.VectorIngestionConfiguration.CustomTransformationConfiguration.IntermediateStorage.S3Location.URI",
	"The intermediate storage URI is on the data source bucket; CreateDataSource fails with \"A custom transformation configuration cannot have the same s3 bucket for intermediate storage as the data source\"",
	"Point IntermediateStorage at a separate bucket",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_CustomTransformationConfiguration.html") if {
	some name in resources_of_type("AWS::Bedrock::DataSource")
	p := _pf_bedrocklib_props(name)
	dsb := _pf_dstb_norm(_pf_dstb_bucket(object.get(object.get(object.get(p, "DataSourceConfiguration", {}), "S3Configuration", {}), "BucketArn", null)))
	uri := object.get(object.get(object.get(object.get(object.get(p, "VectorIngestionConfiguration", {}), "CustomTransformationConfiguration", {}), "IntermediateStorage", {}), "S3Location", {}), "URI", null)
	_pf_dstb_norm(_pf_dstb_bucket(uri)) == dsb
}
