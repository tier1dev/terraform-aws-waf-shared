"""
Tests for the WAF count-mode report.

These exercise the parsing and aggregation against synthetic log records shaped
like real WAFv2 output. The CloudWatch calls are a thin boto3 wrapper and are
covered only where their failure handling matters.
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

import waf_count_report as report  # noqa: E402


def make_record(
    count_rules=(),
    group_count_rules=(),
    excluded_as_count=(),
    action='ALLOW',
    uri='/api/checkout',
    client_ip='203.0.113.10',
    country='US',
    user_agent_value='curl/8.4.0',
    terminating_rule=None,
):
    """
    Build a WAF log record.

    Args:
        count_rules: Rule ids counted at the web ACL level
        group_count_rules: (group id, rule id) pairs counted inside a rule group
        excluded_as_count: (group id, rule id) pairs downgraded by a per-rule override
        action: The action WAF actually took on this request
        uri: Request URI
        client_ip: Source address
        country: Source country
        user_agent_value: User-Agent header value
        terminating_rule: (group id, rule id) that actually terminated evaluation

    Returns:
        A dict shaped like a WAFv2 log record
    """
    groups = {}

    for group_id, rule_id in group_count_rules:
        entry = groups.setdefault(group_id, {'ruleGroupId': group_id})
        entry.setdefault('nonTerminatingMatchingRules', []).append(
            {'ruleId': rule_id, 'action': 'COUNT'}
        )

    for group_id, rule_id in excluded_as_count:
        entry = groups.setdefault(group_id, {'ruleGroupId': group_id})
        entry.setdefault('excludedRules', []).append(
            {'ruleId': rule_id, 'exclusionType': 'EXCLUDED_AS_COUNT'}
        )

    if terminating_rule:
        group_id, rule_id = terminating_rule
        entry = groups.setdefault(group_id, {'ruleGroupId': group_id})
        entry['terminatingRule'] = {'ruleId': rule_id, 'action': 'BLOCK'}

    return {
        'action': action,
        'terminatingRuleId': 'Default_Action',
        'nonTerminatingMatchingRules': [
            {'ruleId': rule_id, 'action': 'COUNT'} for rule_id in count_rules
        ],
        'ruleGroupList': list(groups.values()),
        'httpRequest': {
            'clientIp': client_ip,
            'country': country,
            'uri': uri,
            'httpMethod': 'POST',
            'headers': [
                {'name': 'Host', 'value': 'example.com'},
                {'name': 'User-Agent', 'value': user_agent_value},
            ],
        },
    }


COMMON = 'AWS#AWSManagedRulesCommonRuleSet'
BAD_INPUTS = 'AWS#AWSManagedRulesKnownBadInputsRuleSet'


class TestIterCountMatches:
    def test_finds_group_level_count_matches(self):
        record = make_record(group_count_rules=[(COMMON, 'SQLi_BODY')])

        assert list(report.iter_count_matches(record)) == [(COMMON, 'SQLi_BODY')]

    def test_finds_web_acl_level_count_matches(self):
        record = make_record(count_rules=['rate-limit'])

        assert list(report.iter_count_matches(record)) == [
            (report.WEB_ACL_GROUP, 'rate-limit')
        ]

    def test_finds_per_rule_overrides(self):
        record = make_record(excluded_as_count=[(COMMON, 'SizeRestrictions_BODY')])

        assert list(report.iter_count_matches(record)) == [
            (COMMON, 'SizeRestrictions_BODY')
        ]

    def test_ignores_terminating_rules(self):
        record = make_record(action='BLOCK', terminating_rule=(COMMON, 'XSS_BODY'))

        assert list(report.iter_count_matches(record)) == []

    def test_ignores_non_count_non_terminating_rules(self):
        record = make_record()
        record['nonTerminatingMatchingRules'] = [
            {'ruleId': 'captcha-rule', 'action': 'CAPTCHA'}
        ]

        assert list(report.iter_count_matches(record)) == []

    def test_ignores_non_count_actions_inside_a_rule_group(self):
        # rule_action_override can set a rule inside a group to CAPTCHA or
        # CHALLENGE. Those are enforcing already, so they are not count matches.
        record = make_record()
        record['ruleGroupList'] = [
            {
                'ruleGroupId': COMMON,
                'nonTerminatingMatchingRules': [
                    {'ruleId': 'captcha-rule', 'action': 'CAPTCHA'},
                    {'ruleId': 'challenge-rule', 'action': 'CHALLENGE'},
                ],
            }
        ]

        assert list(report.iter_count_matches(record)) == []

    def test_separates_count_from_non_count_within_one_group(self):
        record = make_record()
        record['ruleGroupList'] = [
            {
                'ruleGroupId': COMMON,
                'nonTerminatingMatchingRules': [
                    {'ruleId': 'captcha-rule', 'action': 'CAPTCHA'},
                    {'ruleId': 'SQLi_BODY', 'action': 'COUNT'},
                ],
            }
        ]

        assert list(report.iter_count_matches(record)) == [(COMMON, 'SQLi_BODY')]

    def test_handles_records_with_no_rule_data(self):
        assert list(report.iter_count_matches({})) == []

    def test_handles_explicit_nulls(self):
        # WAF emits null rather than [] for these when nothing matched.
        record = {'nonTerminatingMatchingRules': None, 'ruleGroupList': None}

        assert list(report.iter_count_matches(record)) == []


class TestUserAgent:
    def test_is_case_insensitive(self):
        assert report.user_agent({'headers': [{'name': 'user-agent', 'value': 'x'}]}) == 'x'

    def test_defaults_when_absent(self):
        assert report.user_agent({'headers': [{'name': 'Host', 'value': 'a'}]}) == '-'

    def test_defaults_when_headers_missing(self):
        assert report.user_agent({}) == '-'


class TestSummarise:
    def test_counts_requests_not_rule_matches(self):
        # One request matching three rules is one request that would be blocked.
        records = [
            make_record(
                group_count_rules=[
                    (COMMON, 'SQLi_BODY'),
                    (COMMON, 'XSS_BODY'),
                    (BAD_INPUTS, 'Host_localhost'),
                ]
            )
        ]

        summary = report.summarise(records, total_requests=100)

        assert summary['matched_requests'] == 1
        assert summary['new_block_requests'] == 1
        assert summary['new_block_percent'] == 1.0

    def test_excludes_requests_already_blocked(self):
        # Enforcing a counted rule changes nothing for a request another rule
        # already blocks, so it must not inflate the projected impact.
        records = [
            make_record(group_count_rules=[(COMMON, 'SQLi_BODY')], action='BLOCK'),
            make_record(group_count_rules=[(COMMON, 'SQLi_BODY')], action='ALLOW'),
        ]

        summary = report.summarise(records, total_requests=100)

        assert summary['matched_requests'] == 2
        assert summary['new_block_requests'] == 1
        assert summary['groups'][0]['matched_requests'] == 2
        assert summary['groups'][0]['new_block_requests'] == 1

    def test_captcha_requests_still_count_as_newly_blocked(self):
        records = [make_record(group_count_rules=[(COMMON, 'SQLi_BODY')], action='CAPTCHA')]

        assert report.summarise(records, 10)['new_block_requests'] == 1

    def test_deduplicates_per_group_across_rules(self):
        records = [
            make_record(
                group_count_rules=[(COMMON, 'SQLi_BODY'), (COMMON, 'XSS_BODY')]
            )
        ]

        summary = report.summarise(records, total_requests=10)
        common = next(g for g in summary['groups'] if g['rule_group'] == COMMON)

        assert common['matched_requests'] == 1
        assert common['new_block_requests'] == 1

    def test_groups_sorted_by_impact(self):
        records = [make_record(group_count_rules=[(COMMON, 'SQLi_BODY')]) for _ in range(5)]
        records += [make_record(group_count_rules=[(BAD_INPUTS, 'Host_localhost')])]

        summary = report.summarise(records, total_requests=100)

        assert summary['groups'][0]['rule_group'] == COMMON
        assert summary['groups'][0]['new_block_requests'] == 5

    def test_rules_sorted_by_match_count(self):
        records = [make_record(group_count_rules=[(COMMON, 'XSS_BODY')]) for _ in range(3)]
        records += [make_record(group_count_rules=[(COMMON, 'SQLi_BODY')])]

        summary = report.summarise(records, total_requests=10)

        assert summary['rules'][0]['rule'] == 'XSS_BODY'
        assert summary['rules'][0]['matches'] == 3

    def test_collects_triage_detail_per_rule(self):
        records = [
            make_record(
                group_count_rules=[(COMMON, 'SQLi_BODY')],
                uri='/api/graphql',
                client_ip='10.0.0.1',
                country='US',
            ),
            make_record(
                group_count_rules=[(COMMON, 'SQLi_BODY')],
                uri='/api/graphql',
                client_ip='10.0.0.2',
                country='DE',
            ),
        ]

        rule = report.summarise(records, total_requests=10)['rules'][0]

        assert rule['matches'] == 2
        assert rule['distinct_client_ips'] == 2
        assert rule['top_uris'] == [('/api/graphql', 2)]
        assert sorted(rule['top_countries']) == [('DE', 1), ('US', 1)]

    def test_caps_samples_per_rule(self):
        records = [make_record(group_count_rules=[(COMMON, 'SQLi_BODY')]) for _ in range(20)]

        rule = report.summarise(records, total_requests=100)['rules'][0]

        assert len(rule['samples']) == report.SAMPLES_PER_RULE
        assert rule['matches'] == 20

    def test_records_without_matches_are_ignored(self):
        summary = report.summarise([make_record(), make_record()], total_requests=50)

        assert summary['matched_requests'] == 0
        assert summary['rules'] == []
        assert summary['new_block_percent'] == 0.0

    def test_zero_total_requests_does_not_divide_by_zero(self):
        records = [make_record(group_count_rules=[(COMMON, 'SQLi_BODY')])]

        summary = report.summarise(records, total_requests=0)

        assert summary['new_block_percent'] == 0.0


class TestFormatText:
    def _summary(self):
        records = [make_record(group_count_rules=[(COMMON, 'SQLi_BODY')])]
        return report.summarise(records, total_requests=100)

    def test_renders_rule_and_group_detail(self):
        from datetime import datetime, timezone

        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        end = datetime(2026, 1, 2, tzinfo=timezone.utc)

        text = report.format_text(self._summary(), 'aws-waf-logs-x', start, end, False)

        assert 'aws-waf-logs-x' in text
        assert COMMON in text
        assert 'SQLi_BODY' in text
        assert '1.00% of traffic' in text
        assert 'WARNING' not in text

    def test_warns_when_results_were_truncated(self):
        from datetime import datetime, timezone

        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        end = datetime(2026, 1, 2, tzinfo=timezone.utc)

        text = report.format_text(self._summary(), 'aws-waf-logs-x', start, end, True)

        assert 'WARNING' in text
        assert 'floor, not a' in text

    def test_reports_empty_windows_plainly(self):
        from datetime import datetime, timezone

        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        end = datetime(2026, 1, 2, tzinfo=timezone.utc)
        summary = report.summarise([], total_requests=500)

        text = report.format_text(summary, 'aws-waf-logs-x', start, end, False)

        assert 'No count-mode matches in this window.' in text


class TestFetchCountRecords:
    def _client(self, results):
        client = MagicMock()
        client.start_query.return_value = {'queryId': 'q-1'}
        client.get_query_results.return_value = {'status': 'Complete', 'results': results}
        return client

    def test_parses_messages_and_flags_truncation(self):
        message = json.dumps(make_record(group_count_rules=[(COMMON, 'SQLi_BODY')]))
        client = self._client([[{'field': '@message', 'value': message}]])

        records, truncated = self._fetch(client, limit=1)

        assert len(records) == 1
        assert truncated is True

    def test_not_truncated_below_the_limit(self):
        message = json.dumps(make_record())
        client = self._client([[{'field': '@message', 'value': message}]])

        _, truncated = self._fetch(client, limit=10)

        assert truncated is False

    def test_skips_unparseable_records(self, capsys):
        client = self._client(
            [
                [{'field': '@message', 'value': 'not json'}],
                [{'field': '@message', 'value': json.dumps(make_record())}],
            ]
        )

        records, _ = self._fetch(client, limit=10)

        assert len(records) == 1
        assert 'unparseable' in capsys.readouterr().err

    def _fetch(self, client, limit):
        from datetime import datetime, timezone

        return report.fetch_count_records(
            client,
            'aws-waf-logs-x',
            datetime(2026, 1, 1, tzinfo=timezone.utc),
            datetime(2026, 1, 2, tzinfo=timezone.utc),
            limit,
        )


class TestRunQuery:
    def test_raises_on_failed_query(self):
        from datetime import datetime, timezone

        client = MagicMock()
        client.start_query.return_value = {'queryId': 'q-1'}
        client.get_query_results.return_value = {'status': 'Failed', 'results': []}

        with pytest.raises(RuntimeError, match='ended with status Failed'):
            report.run_query(
                client,
                'aws-waf-logs-x',
                'fields @message',
                datetime(2026, 1, 1, tzinfo=timezone.utc),
                datetime(2026, 1, 2, tzinfo=timezone.utc),
                limit=1,
            )


class TestFetchTotalRequests:
    def test_reads_the_stats_field(self):
        from datetime import datetime, timezone

        client = MagicMock()
        client.start_query.return_value = {'queryId': 'q-1'}
        client.get_query_results.return_value = {
            'status': 'Complete',
            'results': [[{'field': 'total', 'value': '4321'}]],
        }

        total = report.fetch_total_requests(
            client,
            'aws-waf-logs-x',
            datetime(2026, 1, 1, tzinfo=timezone.utc),
            datetime(2026, 1, 2, tzinfo=timezone.utc),
        )

        assert total == 4321

    def test_returns_zero_for_an_empty_window(self):
        from datetime import datetime, timezone

        client = MagicMock()
        client.start_query.return_value = {'queryId': 'q-1'}
        client.get_query_results.return_value = {'status': 'Complete', 'results': []}

        total = report.fetch_total_requests(
            client,
            'aws-waf-logs-x',
            datetime(2026, 1, 1, tzinfo=timezone.utc),
            datetime(2026, 1, 2, tzinfo=timezone.utc),
        )

        assert total == 0


class NotFound(Exception):
    """Stand-in for the client's ResourceNotFoundException."""


class TestMain:
    def _install_client(self, monkeypatch, records, total='1000'):
        """Wire a fake logs client returning the given records into main()."""
        client = MagicMock()
        client.exceptions.ResourceNotFoundException = NotFound
        client.start_query.return_value = {'queryId': 'q-1'}

        responses = [
            {'status': 'Complete', 'results': [[{'field': 'total', 'value': total}]]},
            {
                'status': 'Complete',
                'results': [
                    [{'field': '@message', 'value': json.dumps(r)}] for r in records
                ],
            },
        ]
        client.get_query_results.side_effect = responses
        monkeypatch.setattr(report.boto3, 'client', lambda *a, **k: client)
        return client

    def test_passes_when_under_the_threshold(self, monkeypatch, capsys):
        # 1 blocked request in 1000 = 0.1%, under the 1% budget.
        self._install_client(
            monkeypatch, [make_record(group_count_rules=[(COMMON, 'SQLi_BODY')])]
        )

        code = report.main(['--name', 'acl', '--max-block-percent', '1.0'])

        assert code == 0
        assert 'FAIL' not in capsys.readouterr().err

    def test_fails_when_over_the_threshold(self, monkeypatch, capsys):
        records = [make_record(group_count_rules=[(COMMON, 'SQLi_BODY')]) for _ in range(50)]
        self._install_client(monkeypatch, records, total='1000')

        code = report.main(['--name', 'acl', '--max-block-percent', '1.0'])

        assert code == 1
        assert 'exceeds the 1.00% threshold' in capsys.readouterr().err

    def test_exactly_at_the_threshold_passes(self, monkeypatch):
        # A 1% budget means 1% is acceptable, not a failure. Getting this
        # backwards fails pipelines that are exactly within budget.
        self._install_client(
            monkeypatch,
            [make_record(group_count_rules=[(COMMON, 'SQLi_BODY')])],
            total='100',
        )

        assert report.main(['--name', 'acl', '--max-block-percent', '1.0']) == 0

    def test_just_over_the_threshold_fails(self, monkeypatch):
        records = [make_record(group_count_rules=[(COMMON, 'SQLi_BODY')]) for _ in range(2)]
        self._install_client(monkeypatch, records, total='100')

        assert report.main(['--name', 'acl', '--max-block-percent', '1.0']) == 1

    def test_no_threshold_never_fails(self, monkeypatch):
        records = [make_record(group_count_rules=[(COMMON, 'SQLi_BODY')]) for _ in range(500)]
        self._install_client(monkeypatch, records, total='500')

        assert report.main(['--name', 'acl']) == 0

    def test_derives_the_log_group_from_the_acl_name(self, monkeypatch):
        client = self._install_client(monkeypatch, [])

        report.main(['--name', 'my-acl'])

        assert client.start_query.call_args.kwargs['logGroupName'] == 'aws-waf-logs-my-acl'

    def test_explicit_log_group_is_used_verbatim(self, monkeypatch):
        client = self._install_client(monkeypatch, [])

        report.main(['--log-group', 'some-other-group'])

        assert client.start_query.call_args.kwargs['logGroupName'] == 'some-other-group'

    def test_json_output_is_machine_readable(self, monkeypatch, capsys):
        self._install_client(
            monkeypatch, [make_record(group_count_rules=[(COMMON, 'SQLi_BODY')])]
        )

        report.main(['--name', 'acl', '--format', 'json'])

        payload = json.loads(capsys.readouterr().out)
        assert payload['new_block_requests'] == 1
        assert payload['groups'][0]['rule_group'] == COMMON

    def test_missing_log_group_explains_enable_logging(self, monkeypatch, capsys):
        client = MagicMock()
        client.exceptions.ResourceNotFoundException = NotFound
        client.start_query.side_effect = NotFound()
        monkeypatch.setattr(report.boto3, 'client', lambda *a, **k: client)

        code = report.main(['--name', 'acl'])

        assert code == 2
        assert 'enable_logging = true' in capsys.readouterr().err

    def test_limit_is_capped_at_the_insights_maximum(self, monkeypatch):
        client = self._install_client(monkeypatch, [])

        report.main(['--name', 'acl', '--limit', '999999'])

        assert client.start_query.call_args.kwargs['limit'] == report.MAX_QUERY_LIMIT


class TestParseArgs:
    def test_derives_the_module_log_group_name(self):
        args = report.parse_args(['--name', 'my-acl'])

        assert args.name == 'my-acl'
        assert args.log_group is None

    def test_requires_a_target(self):
        with pytest.raises(SystemExit):
            report.parse_args([])

    def test_rejects_both_targets(self):
        with pytest.raises(SystemExit):
            report.parse_args(['--name', 'a', '--log-group', 'b'])
