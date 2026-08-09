#!/usr/bin/env python3
"""
Report what a WAF web ACL would block if its count-mode rules were enforced.

Running a managed rule group with ``override_action = "count"`` records matches
without blocking anything. This reads those matches back out of the module's
CloudWatch log group and answers the question that decides whether the group is
safe to enforce: how much real traffic would have been blocked, by which rule,
and against which URIs.

Counting rule matches alone overstates the impact. One request can match several
count rules, and a request already blocked by an enforcing rule would not change
outcome if a counted rule were enforced too. This deduplicates by request and
reports net-new blocks separately.

Usage:
    ./waf_count_report.py --name my-acl --hours 24
    ./waf_count_report.py --log-group aws-waf-logs-my-acl --hours 168 --format json
    ./waf_count_report.py --name my-acl --max-block-percent 0.5   # non-zero exit if exceeded

CLOUDFRONT-scoped web ACLs log to us-east-1 regardless of where the origin runs,
so pass --region us-east-1 for those.
"""

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

import boto3

# Action recorded against a rule that matched without terminating evaluation.
COUNT_ACTION = 'COUNT'

# Set on rules downgraded to count by a per-rule override rather than a
# group-level one. Older ACLs and rule_action_override both produce these.
EXCLUDED_AS_COUNT = 'EXCLUDED_AS_COUNT'

# Label for count matches from rules defined directly on the web ACL rather than
# inside a managed rule group.
WEB_ACL_GROUP = '(web ACL rules)'

# Insights caps a single query at 10,000 rows.
MAX_QUERY_LIMIT = 10_000

QUERY_POLL_SECONDS = 1
QUERY_TIMEOUT_SECONDS = 300

SAMPLES_PER_RULE = 3
TOP_N = 5


def iter_count_matches(record):
    """
    Yield every (rule group, rule) pair this request matched in count mode.

    Args:
        record: A parsed WAF log record

    Yields:
        Tuples of (rule group id, rule id)
    """
    for rule in record.get('nonTerminatingMatchingRules') or []:
        if rule.get('action') == COUNT_ACTION:
            yield (WEB_ACL_GROUP, rule.get('ruleId', 'unknown'))

    for group in record.get('ruleGroupList') or []:
        group_id = group.get('ruleGroupId', 'unknown')

        # A group-level override to count puts matches here.
        for rule in group.get('nonTerminatingMatchingRules') or []:
            if rule.get('action') == COUNT_ACTION:
                yield (group_id, rule.get('ruleId', 'unknown'))

        # A per-rule override puts them here instead.
        for rule in group.get('excludedRules') or []:
            if rule.get('exclusionType') == EXCLUDED_AS_COUNT:
                yield (group_id, rule.get('ruleId', 'unknown'))


def user_agent(http_request):
    """
    Pull the User-Agent out of a WAF log record's header list.

    Args:
        http_request: The httpRequest object from a WAF log record

    Returns:
        The User-Agent value, or '-' when absent
    """
    for header in http_request.get('headers') or []:
        if header.get('name', '').lower() == 'user-agent':
            return header.get('value', '-')
    return '-'


def new_rule_stats():
    """Return an empty per-rule statistics accumulator."""
    return {
        'matches': 0,
        'new_blocks': 0,
        'client_ips': Counter(),
        'uris': Counter(),
        'countries': Counter(),
        'user_agents': Counter(),
        'samples': [],
    }


def record_sample(stats, record):
    """
    Fold one matching request into a rule's statistics.

    Args:
        stats: The accumulator from new_rule_stats
        record: A parsed WAF log record
    """
    http_request = record.get('httpRequest') or {}

    stats['matches'] += 1
    stats['client_ips'][http_request.get('clientIp', '-')] += 1
    stats['uris'][http_request.get('uri', '-')] += 1
    stats['countries'][http_request.get('country', '-')] += 1
    stats['user_agents'][user_agent(http_request)] += 1

    if len(stats['samples']) < SAMPLES_PER_RULE:
        stats['samples'].append(
            {
                'uri': http_request.get('uri', '-'),
                'method': http_request.get('httpMethod', '-'),
                'client_ip': http_request.get('clientIp', '-'),
                'country': http_request.get('country', '-'),
                'user_agent': user_agent(http_request),
                'current_action': record.get('action', '-'),
            }
        )


def summarise(records, total_requests):
    """
    Aggregate count-mode matches across a set of WAF log records.

    Args:
        records: Parsed WAF log records
        total_requests: Total requests the web ACL saw in the same window, used
            as the denominator for impact percentages

    Returns:
        dict with overall impact, per-group impact and per-rule detail
    """
    rules = {}
    group_matched = defaultdict(set)
    group_new_blocks = defaultdict(set)
    matched_requests = set()
    new_block_requests = set()

    for index, record in enumerate(records):
        matches = set(iter_count_matches(record))
        if not matches:
            continue

        # A request already blocked by an enforcing rule would not change
        # outcome if a counted rule started enforcing as well.
        already_blocked = record.get('action') == 'BLOCK'

        matched_requests.add(index)
        if not already_blocked:
            new_block_requests.add(index)

        for group_id, rule_id in matches:
            group_matched[group_id].add(index)
            if not already_blocked:
                group_new_blocks[group_id].add(index)

            stats = rules.setdefault((group_id, rule_id), new_rule_stats())
            record_sample(stats, record)
            if not already_blocked:
                stats['new_blocks'] += 1

    return {
        'total_requests': total_requests,
        'matched_requests': len(matched_requests),
        'new_block_requests': len(new_block_requests),
        'new_block_percent': percent(len(new_block_requests), total_requests),
        'groups': build_group_rows(group_matched, group_new_blocks, total_requests),
        'rules': build_rule_rows(rules),
    }


def percent(part, whole):
    """Return part/whole as a percentage, or 0.0 when whole is zero."""
    return (part / whole * 100) if whole else 0.0


def build_group_rows(group_matched, group_new_blocks, total_requests):
    """
    Build the per-rule-group impact rows, worst first.

    Args:
        group_matched: Map of group id to the set of matching request indices
        group_new_blocks: Map of group id to indices that would be newly blocked
        total_requests: Denominator for impact percentages

    Returns:
        List of dicts sorted by new block count, descending
    """
    rows = [
        {
            'rule_group': group_id,
            'matched_requests': len(indices),
            'new_block_requests': len(group_new_blocks.get(group_id, ())),
            'new_block_percent': percent(
                len(group_new_blocks.get(group_id, ())), total_requests
            ),
        }
        for group_id, indices in group_matched.items()
    ]
    return sorted(rows, key=lambda row: row['new_block_requests'], reverse=True)


def build_rule_rows(rules):
    """
    Build the per-rule detail rows, worst first.

    Args:
        rules: Map of (group id, rule id) to a statistics accumulator

    Returns:
        List of dicts sorted by match count, descending
    """
    rows = [
        {
            'rule_group': group_id,
            'rule': rule_id,
            'matches': stats['matches'],
            'new_blocks': stats['new_blocks'],
            'distinct_client_ips': len(stats['client_ips']),
            'top_uris': stats['uris'].most_common(TOP_N),
            'top_client_ips': stats['client_ips'].most_common(TOP_N),
            'top_countries': stats['countries'].most_common(TOP_N),
            'top_user_agents': stats['user_agents'].most_common(TOP_N),
            'samples': stats['samples'],
        }
        for (group_id, rule_id), stats in rules.items()
    ]
    return sorted(rows, key=lambda row: row['matches'], reverse=True)


def run_query(logs_client, log_group, query, start, end, limit):
    """
    Run a CloudWatch Logs Insights query to completion.

    Args:
        logs_client: A boto3 CloudWatch Logs client
        log_group: Log group name to query
        query: The Insights query string
        start: Window start as a datetime
        end: Window end as a datetime

    Returns:
        The query's result rows, each a list of {'field': ..., 'value': ...}

    Raises:
        RuntimeError: If the query fails, is cancelled, or does not finish in time
    """
    started = logs_client.start_query(
        logGroupName=log_group,
        startTime=int(start.timestamp()),
        endTime=int(end.timestamp()),
        queryString=query,
        limit=limit,
    )
    query_id = started['queryId']
    deadline = time.monotonic() + QUERY_TIMEOUT_SECONDS

    while time.monotonic() < deadline:
        response = logs_client.get_query_results(queryId=query_id)
        status = response['status']

        if status == 'Complete':
            return response['results']
        if status in ('Failed', 'Cancelled', 'Timeout'):
            raise RuntimeError(f"Insights query {query_id} ended with status {status}")

        time.sleep(QUERY_POLL_SECONDS)

    logs_client.stop_query(queryId=query_id)
    raise RuntimeError(
        f"Insights query {query_id} did not finish within {QUERY_TIMEOUT_SECONDS}s. "
        "Narrow the window with --hours."
    )


def field_value(row, name):
    """Pull one named field out of an Insights result row."""
    for field in row:
        if field.get('field') == name:
            return field.get('value')
    return None


def fetch_total_requests(logs_client, log_group, start, end):
    """
    Count every request the web ACL logged in the window.

    This is the denominator for impact percentages. It is a separate query so the
    match query can filter server-side and stay small.

    Args:
        logs_client: A boto3 CloudWatch Logs client
        log_group: Log group name to query
        start: Window start as a datetime
        end: Window end as a datetime

    Returns:
        Total request count as an int
    """
    results = run_query(
        logs_client, log_group, 'stats count(*) as total', start, end, limit=1
    )
    if not results:
        return 0

    return int(float(field_value(results[0], 'total') or 0))


def fetch_count_records(logs_client, log_group, start, end, limit):
    """
    Fetch WAF log records that contain at least one count-mode match.

    The ``like /COUNT/`` filter is a cheap server-side narrowing on the raw
    message. It can let through records that merely mention the string, so
    iter_count_matches re-checks each record structurally.

    Args:
        logs_client: A boto3 CloudWatch Logs client
        log_group: Log group name to query
        start: Window start as a datetime
        end: Window end as a datetime
        limit: Maximum rows to return

    Returns:
        Tuple of (parsed records, whether the row limit was hit)
    """
    query = 'fields @message | filter @message like /COUNT/ | sort @timestamp desc'
    results = run_query(logs_client, log_group, query, start, end, limit)

    records = []
    for row in results:
        message = field_value(row, '@message')
        if not message:
            continue
        try:
            records.append(json.loads(message))
        except json.JSONDecodeError:
            print(f"warning: skipping unparseable log record: {message[:120]}", file=sys.stderr)

    return records, len(results) >= limit


def format_group_section(summary):
    """Render the per-rule-group impact table."""
    lines = ['Impact by rule group (what enforcing this group would newly block)', '']
    header = f"  {'RULE GROUP':<52} {'MATCHED':>9} {'NEW BLOCKS':>11} {'% TRAFFIC':>10}"
    lines.append(header)
    lines.append(f"  {'-' * 52} {'-' * 9} {'-' * 11} {'-' * 10}")

    for row in summary['groups']:
        lines.append(
            f"  {row['rule_group']:<52} {row['matched_requests']:>9} "
            f"{row['new_block_requests']:>11} {row['new_block_percent']:>9.2f}%"
        )

    return lines


def format_rule_section(rule):
    """Render the detail block for a single rule."""
    lines = [
        f"  {rule['rule_group']} / {rule['rule']}",
        f"    matches: {rule['matches']}   would newly block: {rule['new_blocks']}"
        f"   distinct client IPs: {rule['distinct_client_ips']}",
    ]

    for label, key in (
        ('top URIs', 'top_uris'),
        ('top IPs', 'top_client_ips'),
        ('top countries', 'top_countries'),
        ('top agents', 'top_user_agents'),
    ):
        rendered = ', '.join(f"{value} ({count})" for value, count in rule[key])
        lines.append(f"    {label + ':':<16}{rendered}")

    for sample in rule['samples']:
        lines.append(
            f"    e.g. {sample['method']} {sample['uri']} "
            f"from {sample['client_ip']} ({sample['country']}) "
            f"currently {sample['current_action']}"
        )

    lines.append('')
    return lines


def format_text(summary, log_group, start, end, truncated):
    """
    Render the full human-readable report.

    Args:
        summary: Output of summarise
        log_group: Log group that was queried
        start: Window start as a datetime
        end: Window end as a datetime
        truncated: Whether the Insights row limit was hit

    Returns:
        The report as a string
    """
    lines = [
        '',
        f"WAF count-mode report for {log_group}",
        f"Window: {start.isoformat()} to {end.isoformat()}",
        '',
        f"{'Total requests logged:':<32}{summary['total_requests']}",
        f"{'Requests matching a count rule:':<32}{summary['matched_requests']}",
        f"{'Would be newly blocked:':<32}{summary['new_block_requests']} "
        f"({summary['new_block_percent']:.2f}% of traffic)",
        '',
    ]

    if truncated:
        lines += [
            f"WARNING: hit the {MAX_QUERY_LIMIT}-row query limit. Counts are a floor, not a",
            '         total. Narrow the window with --hours for an accurate picture.',
            '',
        ]

    if not summary['rules']:
        lines += ['No count-mode matches in this window.', '']
        return '\n'.join(lines)

    lines += format_group_section(summary)
    lines += ['', 'Rule detail (highest match count first)', '']

    for rule in summary['rules']:
        lines += format_rule_section(rule)

    return '\n'.join(lines)


def parse_args(argv=None):
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument(
        '--name',
        help="Web ACL name. The log group is derived as aws-waf-logs-<name>, matching "
        "the naming this module enforces.",
    )
    target.add_argument('--log-group', help='CloudWatch log group name to read directly.')

    parser.add_argument(
        '--hours', type=float, default=24, help='Hours to look back (default: 24).'
    )
    parser.add_argument('--region', help='AWS region. CLOUDFRONT-scoped ACLs log to us-east-1.')
    parser.add_argument(
        '--limit',
        type=int,
        default=MAX_QUERY_LIMIT,
        help=f'Maximum matching records to fetch (max {MAX_QUERY_LIMIT}).',
    )
    parser.add_argument(
        '--format', choices=('text', 'json'), default='text', help='Output format.'
    )
    parser.add_argument(
        '--max-block-percent',
        type=float,
        help='Exit non-zero if the projected new block rate exceeds this percentage. '
        'Use to gate a pipeline before flipping a group to enforcing.',
    )
    return parser.parse_args(argv)


def main(argv=None):
    """Entry point. Returns the process exit code."""
    args = parse_args(argv)

    log_group = args.log_group or f'aws-waf-logs-{args.name}'
    limit = min(args.limit, MAX_QUERY_LIMIT)
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=args.hours)

    logs_client = boto3.client('logs', region_name=args.region)

    try:
        total_requests = fetch_total_requests(logs_client, log_group, start, end)
        records, truncated = fetch_count_records(logs_client, log_group, start, end, limit)
    except logs_client.exceptions.ResourceNotFoundException:
        print(
            f"error: log group {log_group} not found. The module creates it only when "
            "enable_logging = true; check that, and that --region matches the ACL scope.",
            file=sys.stderr,
        )
        return 2

    summary = summarise(records, total_requests)

    if args.format == 'json':
        print(json.dumps(summary, indent=2, default=str))
    else:
        print(format_text(summary, log_group, start, end, truncated))

    if args.max_block_percent is not None:
        if summary['new_block_percent'] > args.max_block_percent:
            print(
                f"FAIL: projected new block rate {summary['new_block_percent']:.2f}% "
                f"exceeds the {args.max_block_percent:.2f}% threshold.",
                file=sys.stderr,
            )
            return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
