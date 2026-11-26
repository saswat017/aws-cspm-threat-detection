"""EventBridge event-pattern matching, implemented in Python.

The same pattern.json files are deployed as real EventBridge rules by Terraform
(on real AWS) and evaluated by this matcher (in the emulator and in tests).

Supported (a subset of EventBridge syntax, enough for our rules):
  {"key": [v1, v2]}            value equals any of the listed values
  {"key": {...}}               nested match
  {"prefix": "Delete"}         string starts with
  {"suffix": ".json"}          string ends with
  {"anything-but": [...]}      value is none of these
  {"exists": true/false}       key is present / absent
  {"equals-ignore-case": "x"}
  "$or": [pattern, pattern]    any of the sub-patterns matches
If the event value is a list, the rule matches when ANY element matches
(this is how EventBridge treats arrays).
"""

_MISSING = object()


def matches(pattern: dict, event) -> bool:
    for key, expected in pattern.items():
        if key == "$or":
            if not any(matches(sub, event) for sub in expected):
                return False
            continue
        actual = event.get(key, _MISSING) if isinstance(event, dict) else _MISSING
        if isinstance(expected, dict):
            if not _match_nested(expected, actual):
                return False
        elif not _match_values(expected, actual):
            return False
    return True


def _match_nested(pattern, actual):
    if isinstance(actual, list):                 # array: any element may match
        return any(_match_nested(pattern, item) for item in actual)
    return isinstance(actual, dict) and matches(pattern, actual)


def _match_values(allowed: list, actual) -> bool:
    if isinstance(actual, list):
        return any(_match_values(allowed, item) for item in actual)
    return any(_match_one(rule, actual) for rule in allowed)


def _match_one(rule, actual) -> bool:
    if not isinstance(rule, dict):               # plain value: exact match
        return actual is not _MISSING and actual == rule
    if "exists" in rule:
        return (actual is not _MISSING) == rule["exists"]
    if actual is _MISSING:
        return False
    if "prefix" in rule:
        return isinstance(actual, str) and actual.startswith(rule["prefix"])
    if "suffix" in rule:
        return isinstance(actual, str) and actual.endswith(rule["suffix"])
    if "equals-ignore-case" in rule:
        return isinstance(actual, str) and actual.lower() == rule["equals-ignore-case"].lower()
    if "anything-but" in rule:
        banned = rule["anything-but"]
        banned = banned if isinstance(banned, list) else [banned]
        return actual not in banned
    raise ValueError(f"Unsupported pattern operator: {rule}")


def get_path(data, dotted: str):
    """get_path(event, "detail.userIdentity.arn") -> value or None."""
    for part in dotted.split("."):
        if not isinstance(data, dict):
            return None
        data = data.get(part)
    return data


def to_eventbridge(record: dict) -> dict:
    """Wrap a CloudTrail record the way AWS delivers it to EventBridge."""
    service = record.get("eventSource", "unknown.amazonaws.com").split(".")[0]
    signin = record.get("eventType") == "AwsConsoleSignIn"
    return {
        "version": "0",
        "id": record.get("eventID", ""),
        "detail-type": "AWS Console Sign In via CloudTrail" if signin else "AWS API Call via CloudTrail",
        "source": f"aws.{service}",
        "account": record.get("recipientAccountId", ""),
        "time": record.get("eventTime", ""),
        "region": record.get("awsRegion", ""),
        "resources": [],
        "detail": record,
    }
