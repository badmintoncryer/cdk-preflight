package cdk_preflight

import rego.v1

# The storage location takes a whole bucket: a key prefix in the URI fails
# ("contains a sub-folder which is not supported") and S3Location itself is
# mandatory although the schema leaves it optional (both measured 2026-09-06).
_pf_kbsu_url := "https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_SupplementalDataStorageConfiguration.html"

_pf_kbsu_locs(name) := ls if {
	p := _pf_bedrocklib_props(name)
	ls := object.get(object.get(object.get(object.get(p, "KnowledgeBaseConfiguration", {}), "VectorKnowledgeBaseConfiguration", {}), "SupplementalDataStorageConfiguration", {}), "SupplementalDataStorageLocations", [])
	is_array(ls)
}

_pf_kbsu_path(i) := sprintf("Properties.KnowledgeBaseConfiguration.VectorKnowledgeBaseConfiguration.SupplementalDataStorageConfiguration.SupplementalDataStorageLocations[%d].S3Location", [i])

violation contains make_diag_full("pf-bedrock-kb-supplemental-storage-uri", "ERROR", name,
	_pf_kbsu_path(i),
	"The supplemental data storage location has no S3Location; CreateKnowledgeBase fails with \"s3Location cannot be null\"",
	"Set S3Location.URI to s3://<bucket>",
	_pf_kbsu_url) if {
	some name in resources_of_type("AWS::Bedrock::KnowledgeBase")
	some i, l in _pf_kbsu_locs(name)
	is_object(l)
	not _pf_bedrocklib_has(l, "S3Location")
}

violation contains make_diag_full("pf-bedrock-kb-supplemental-storage-uri", "ERROR", name,
	sprintf("%s.URI", [_pf_kbsu_path(i)]),
	sprintf("Supplemental storage URI '%s' names a key prefix inside the bucket; CreateKnowledgeBase fails with \"The S3 URI for the provided supplemental data storage bucket contains a sub-folder which is not supported\"", [t]),
	"Point the URI at the bucket root (s3://<bucket>), using a dedicated bucket for extracted media",
	_pf_kbsu_url) if {
	some name in resources_of_type("AWS::Bedrock::KnowledgeBase")
	some i, l in _pf_kbsu_locs(name)
	is_object(l)
	t := _pf_bedrocklib_bucket_text(object.get(object.get(l, "S3Location", {}), "URI", null))
	startswith(t, "s3://")
	rest := split(substring(t, 5, -1), "/")
	count(rest) >= 2
	tail := concat("/", array.slice(rest, 1, count(rest)))
	tail != ""
}
