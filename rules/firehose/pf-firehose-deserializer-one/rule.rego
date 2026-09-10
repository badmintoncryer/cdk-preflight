package cdk_preflight

import rego.v1

_pf_pf_firehose_deserializer_one_n(c) := n if {
	fc := object.get(object.get(c, "DataFormatConversionConfiguration", {}), "InputFormatConfiguration", null)
	is_object(fc)
	s := object.get(fc, "Deserializer", null)
	is_object(s)
	n := count([k | some k in {"OpenXJsonSerDe", "HiveJsonSerDe"}; object.get(s, k, "__pf_absent") != "__pf_absent"])
}

violation contains make_diag_full("pf-firehose-deserializer-one", "ERROR", name,
	sprintf("%s.DataFormatConversionConfiguration.InputFormatConfiguration.Deserializer", [path]),
	sprintf("%d deserializers are set; the stream create fails with \"More than one deserializer specified. Only one may be chosen.\"", [n]),
	"Set exactly one of OpenXJsonSerDe / HiveJsonSerDe",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_InputFormatConfiguration.html") if {
	some [name, path, c] in _pf_fhlib_dests
	n := _pf_pf_firehose_deserializer_one_n(c)
	n > 1
}
