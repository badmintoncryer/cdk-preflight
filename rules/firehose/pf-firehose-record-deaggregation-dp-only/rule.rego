package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-record-deaggregation-dp-only", "ERROR", name,
	sprintf("%s.ProcessingConfiguration.Processors.%d", [path, i]),
	"a RecordDeAggregation processor is configured without dynamic partitioning; the stream create fails with \"class com.amazonaws.services.firehose.internal.model.RecordDeAggregationProcessor can only be present when Dynamic Partitioning is enabled.\"",
	"Enable DynamicPartitioningConfiguration, or drop the processor",
	"https://docs.aws.amazon.com/firehose/latest/dev/dynamic-partitioning-multirecord-deaggergation.html") if {
	some [name, path, i, t, _] in _pf_fhlib_procs
	t == "RecordDeAggregation"
	not _pf_fhlib_dp_enabled(name, path)
}
