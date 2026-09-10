package cdk_preflight

import rego.v1

_pf_fhhtf_bad contains [name, path, f] if {
	some [name, path, c] in _pf_fhlib_dests
	ifc := object.get(object.get(c, "DataFormatConversionConfiguration", {}), "InputFormatConfiguration", null)
	is_object(ifc)
	hive := object.get(object.get(ifc, "Deserializer", {}), "HiveJsonSerDe", null)
	is_object(hive)
	fs := object.get(hive, "TimestampFormats", null)
	is_array(fs)
	some f in fs
	_pf_fhlib_lit(f)
	unquoted := regex.replace(f, `'[^']*'`, "")
	some i in numbers.range(0, count(unquoted) - 1)
	substring(unquoted, i, 1) in _pf_fhlib_ts_bad
}

violation contains make_diag_full("pf-firehose-hive-timestamp-formats", "ERROR", name,
	sprintf("%s.DataFormatConversionConfiguration.InputFormatConfiguration.Deserializer.HiveJsonSerDe.TimestampFormats", [path]),
	sprintf("'%s' is not a Joda time pattern; the stream create fails with \"One or more SerDe options are invalid for org.apache.hcatalog.data.JsonSerDe: [Key: timestamp.formats Value: %s]\"", [f, f]),
	"Use a Joda pattern such as yyyy-MM-dd'T'HH:mm:ss (C I J P R T U V b f i j l o p r t are not pattern letters)",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_HiveJsonSerDe.html") if {
	some [name, path, f] in _pf_fhhtf_bad
}
