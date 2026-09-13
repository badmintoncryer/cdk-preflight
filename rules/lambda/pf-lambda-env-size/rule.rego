package cdk_preflight

import rego.v1

# リテラル文字列のキー/値だけを数える（トークンはスキップ）。サービスが数えるのは
# シリアライズ後のバイト数で、`{"K":"V"}` の引用符・コロン・カンマ・波括弧が変数ごとに
# 6 バイト＋全体で 1 バイト乗る（2026-09-13 実測: 合計 4097 の 1 変数に対して
# "Measured size: 4104 bytes"）。トークンの中身は数えられないので、この値は実サイズの
# 下限にしかならない＝誤検出は出ない。
# NOTE: このエンジンの Rego パーサは内包表記内の 2 変数 some（some k, v in vars）を
# 受け付けないため、object.keys 経由で書く。
_pf_lenv_size(vars) := sum([s |
	some k in object.keys(vars)
	is_string(vars[k])
	s := count(k) + count(vars[k])
])

violation contains make_diag_full("pf-lambda-env-size", "ERROR", name,
	"Properties.Environment.Variables",
	sprintf("Environment variables serialize to at least %d bytes (literal keys and values), but Lambda limits the environment to 4096 bytes; CreateFunction fails at deploy time", [total]),
	"Move large values to SSM Parameter Store, Secrets Manager, or a bundled config file",
	"https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html") if {
	some name in resources_of_type("AWS::Lambda::Function")
	vars := resolve(name, "Properties.Environment.Variables")
	is_object(vars)
	total := _pf_lenv_size(vars) + (6 * count(object.keys(vars))) + 1
	total > 4096
}
