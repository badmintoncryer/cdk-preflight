package cdk_preflight

import rego.v1

_pf_pf_firehose_serializer_required_n(c) := n if {
	fc := object.get(object.get(c, "DataFormatConversionConfiguration", {}), "OutputFormatConfiguration", null)
	is_object(fc)
	s := object.get(fc, "Serializer", null)
	is_object(s)
	n := count([k | some k in {"ParquetSerDe", "OrcSerDe"}; object.get(s, k, "__pf_absent") != "__pf_absent"])
}

violation contains make_diag_full("pf-firehose-serializer-required", "ERROR", name,
	sprintf("%s.DataFormatConversionConfiguration.OutputFormatConfiguration.Serializer", [path]),
	"no serializer is set; the stream create fails with \"Serializer must not be null\"",
	"Set exactly one of ParquetSerDe / OrcSerDe",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_OutputFormatConfiguration.html") if {
	some [name, path, c] in _pf_fhlib_dests
	n := _pf_pf_firehose_serializer_required_n(c)
	n == 0
}
