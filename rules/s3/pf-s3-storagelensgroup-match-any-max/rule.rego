package cdk_preflight

import rego.v1

_pf_s3sgm_fix := "Keep at most 10 prefixes, suffixes or tags per match list"

_pf_s3sgm_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-storagelensgroup-filter.html"

violation contains make_diag_full("pf-s3-storagelensgroup-match-any-max", "ERROR", name,
	sprintf("Properties.Filter.%v", [k]),
	sprintf("%v holds %d entries; Storage Lens groups accept at most 10", [k, n]),
	_pf_s3sgm_fix, _pf_s3sgm_url) if {
	some name in resources_of_type("AWS::S3::StorageLensGroup")
	some k in ["MatchAnyPrefix", "MatchAnySuffix", "MatchAnyTag"]
	n := count(flatten_list(name, sprintf("Properties.Filter.%v", [k])))
	n > 10
}
