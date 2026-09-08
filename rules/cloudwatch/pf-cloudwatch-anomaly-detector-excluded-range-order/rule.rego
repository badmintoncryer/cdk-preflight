package cdk_preflight

import rego.v1

# Both timestamps are matched against the same fixed-width ISO 8601 shape
# first, so the lexicographic comparison below is a chronological one.
_pf_cwetr_ts := `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}`

violation contains make_diag_full("pf-cloudwatch-anomaly-detector-excluded-range-order", "ERROR", name,
	sprintf("Properties.Configuration.ExcludedTimeRanges.%d", [i]),
	sprintf("Excluded time range %d starts at %s and ends at %s; PutAnomalyDetector rejects it with \"Input has invalid parameter.\"", [i, st, et]),
	"Put the earlier timestamp in StartTime",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutAnomalyDetector.html") if {
	some name in resources_of_type("AWS::CloudWatch::AnomalyDetector")
	some item in flatten_list(name, "Properties.Configuration.ExcludedTimeRanges")
	i := item.index
	r := item.value
	is_object(r)
	st := object.get(r, "StartTime", null)
	et := object.get(r, "EndTime", null)
	is_string(st)
	is_string(et)
	regex.match(_pf_cwetr_ts, st)
	regex.match(_pf_cwetr_ts, et)
	st >= et
}
