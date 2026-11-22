from dataclasses import dataclass


DEFAULT_LEVEL = 'medium'

LOW_PAGES = frozenset({'dns_feed_match', 'link_feed_hit', 'login_burst', 'risky_new_device'})
MEDIUM_PAGES = LOW_PAGES | {'new_device', 'new_ports', 'risky_service', 'peer_change',
                           'baseline_missing', 'baseline_mismatch'}


@dataclass(frozen=True)
class Level:
    page_events: frozenset[str]
    quick_calendar: str
    deep_calendar: str | None
    deep_top_ports: int | None


LEVELS = {
    'low': Level(LOW_PAGES, '*-*-* 08:00:00', None, 1000),
    'medium': Level(MEDIUM_PAGES, '*-*-* 08:00:00', 'Mon *-*-* 04:00:00', None),
    'high': Level(
        MEDIUM_PAGES | {'baseline_drift', 'baseline_scope_review', 'coverage', 'needs_human'},
        '*-*-* 02/6:00:00', '*-*-* 04:00:00', None,
    ),
}


def validate_level(level):
    if not isinstance(level, str) or level not in LEVELS:
        raise ValueError('level must be low, medium or high')
    return level
