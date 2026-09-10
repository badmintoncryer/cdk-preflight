package cdk_preflight

import rego.v1

_pf_pf_firehose_serializer_one_n(c) := n if {
	fc := object.get(object.get(c, "DataFormatConversionConfiguration", {}), "OutputFormatConfiguration", null)
	is_object(fc)
	s := object.get(fc, "Serializer", null)
	is_object(s)
	n := count([k | some k in {"ParquetSerDe", "OrcSerDe"}; object.get(s, k, "__pf_absent") != "__pf_absent"])
}

violation contains make_diag_full("pf-firehose-serializer-one", "ERROR", name,
	sprintf("%s.DataFormatConversionConfiguration.OutputFormatConfiguration.Serializer", [path]),
	sprintf("%d serializers are set; the stream create fails with \"More than one serializer specified. Only one may be chosen.\"", [n]),
	"Set exactly one of ParquetSerDe / OrcSerDe",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_OutputFormatConfiguration.html") if {
	some [name, path, c] in _pf_fhlib_dests
	n := _pf_pf_firehose_serializer_one_n(c)
	n > 1
}
