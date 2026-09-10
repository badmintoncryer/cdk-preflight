package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-snowflake-json-mapping-columns", "ERROR", name,
	sprintf("Properties.SnowflakeDestinationConfiguration.%s", [k]),
	sprintf("%s is set while DataLoadingOption is JSON_MAPPING; the stream create fails with \"Can't configure %s when Data Loading Option is not VARIANT_CONTENT_MAPPING or VARIANT_CONTENT_AND_METADATA_MAPPING\"", [k, k]),
	"Drop the column names, or switch to a VARIANT_* data loading option",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_SnowflakeDestinationConfiguration.html") if {
	some [name, path, c] in _pf_fhlib_dests
	path == "Properties.SnowflakeDestinationConfiguration"
	object.get(c, "DataLoadingOption", null) == "JSON_MAPPING"
	some k in {"ContentColumnName", "MetaDataColumnName"}
	object.get(c, k, "__pf_absent") != "__pf_absent"
}
