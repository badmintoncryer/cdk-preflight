package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-snowflake-variant-columns", "ERROR", name,
	sprintf("Properties.SnowflakeDestinationConfiguration.%s", [k]),
	sprintf("DataLoadingOption is VARIANT_CONTENT_AND_METADATA_MAPPING but %s is not set; the stream create fails with \"Must provide ContentColumnName and MetadataColumnName when Data Loading Option is VARIANT_CONTENT_AND_METADATA_MAPPING.\"", [k]),
	"Set both ContentColumnName and MetaDataColumnName",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_SnowflakeDestinationConfiguration.html") if {
	some [name, path, c] in _pf_fhlib_dests
	path == "Properties.SnowflakeDestinationConfiguration"
	object.get(c, "DataLoadingOption", null) == "VARIANT_CONTENT_AND_METADATA_MAPPING"
	some k in {"ContentColumnName", "MetaDataColumnName"}
	object.get(c, k, "__pf_absent") == "__pf_absent"
}
