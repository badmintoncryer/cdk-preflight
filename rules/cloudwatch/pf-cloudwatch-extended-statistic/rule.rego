package cdk_preflight

import rego.v1

# Percentile statistics run p0.0 to p100. Only the pN form is checked; other
# extended forms (tm, wm, tc, ts, ...) have their own grammars and were not
# measured.
#
# 拒否されるのは「100 を超えた値」ではなく「整数部が 100 を超えた値」。
# p100.5 も p100.9999999 も PutMetricAlarm は受け付ける（2026-09-13 us-east-1 実測）
# ので、100 より大きいだけで弾くと誤検出になる。拒否される中で最小なのは p101。
violation contains make_diag_full("pf-cloudwatch-extended-statistic", "ERROR", name,
	"Properties.ExtendedStatistic",
	sprintf("ExtendedStatistic '%s' is beyond p100; PutMetricAlarm fails with \"The value %s for parameter ExtendedStatistic is not supported.\"", [s, s]),
	"Use a percentile between p0.0 and p100",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html#Percentiles") if {
	some name in resources_of_type("AWS::CloudWatch::Alarm")
	s := resolve(name, "Properties.ExtendedStatistic")
	is_string(s)
	startswith(s, "p")
	n := to_number(substring(s, 1, count(s) - 1))
	floor(n) > 100
}
