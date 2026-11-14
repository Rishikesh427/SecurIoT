from ml.securiot_ml.digest import digest


def test_empty_history():
    assert digest([]) == {'summary': 'No audit activity recorded yet.'}


def test_sources_outcomes_and_duplicate_rows_stay_separate():
    rows = [
        {'id': '1', 'actor': 'agent', 'action': 'quarantine', 'outcome': 'would_have'},
        {'id': '2', 'actor': 'judge', 'action': 'restore', 'outcome': 'failed'},
        {'id': '3', 'actor': 'simulator', 'action': 'quarantine', 'outcome': 'applied'},
        {'id': '4', 'actor': 'seeded-demo', 'action': 'restore', 'outcome': 'applied'},
    ]
    summary = digest(rows + [rows[0]])['summary']
    recorded = summary.split('Simulator activity')[0]
    assert '4 available entries' in summary
    assert '0 quarantine(s) reported applied' in recorded
    assert '0 device restore(s) reported applied' in recorded
    assert '1 failed action(s)' in recorded
    assert '1 proposed action(s), not applied' in recorded
    assert 'Simulator activity (1 entries)' in summary
    assert 'Seeded demo history (1 entries)' in summary
