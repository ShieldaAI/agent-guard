"""Fault injection between loading a projection and publishing it.

``import_snapshot`` here is the package's own, with one extra option: ``_after_load``
runs once after the snapshot's rows are loaded and before the publication
transaction. Tests use it to interrupt, race or corrupt an import and prove that
nothing partial is published. The hook is a private module attribute the package
never sets.
"""

from agent_guard_cartography import graph


def import_snapshot(session, snapshot, expected_source, *, _after_load=None, **options):
    graph._after_load_hook = _after_load
    try:
        return graph.import_snapshot(session, snapshot, expected_source, **options)
    finally:
        # An import that returns early (an already-known snapshot) never reaches the hook.
        graph._after_load_hook = None
