package cdk_preflight

import rego.v1

_pf_fhmp_bad contains [name, path, i, "JsonParsingEngine"] if {
	some [name, path, i, t, pr] in _pf_fhlib_procs
	t == "MetadataExtraction"
	not _pf_fhmp_jq(pr)
}

_pf_fhmp_bad contains [name, path, i, "MetadataExtractionQuery"] if {
	some [name, path, i, t, pr] in _pf_fhlib_procs
	t == "MetadataExtraction"
	not _pf_fhlib_has_param(pr, "MetadataExtractionQuery")
}

_pf_fhmp_jq(pr) if {
	some v in _pf_fhlib_params(pr, "JsonParsingEngine")
	v == "JQ-1.6"
}

# An intrinsic parameter value is unknowable, so stay quiet.
_pf_fhmp_jq(pr) if {
	some v in _pf_fhlib_params(pr, "JsonParsingEngine")
	not is_string(v)
}

violation contains make_diag_full("pf-firehose-processor-metadata-params", "ERROR", name,
	sprintf("%s.ProcessingConfiguration.Processors.%d.Parameters", [path, i]),
	sprintf("a MetadataExtraction processor needs %s; the stream create fails with \"MetaDataExtraction JSON Parsing Engine has to be one of JQ-1.6\"", [k]),
	"Give the processor MetadataExtractionQuery and JsonParsingEngine: JQ-1.6",
	"https://docs.aws.amazon.com/firehose/latest/dev/dynamic-partitioning-partitioning-keys.html") if {
	some [name, path, i, k] in _pf_fhmp_bad
}
