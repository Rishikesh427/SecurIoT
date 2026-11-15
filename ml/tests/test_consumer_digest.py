from securiot_ml.digest import consumer_digest


def row(identifier, action, outcome='applied', actor='agent'):
    return dict(id=identifier,action=action,outcome=outcome,actor=actor)


def test_always_three_plain_bullets_even_when_empty():
    bullets=consumer_digest([])
    assert len(bullets)==3
    assert '0 warnings' in bullets[0]
    assert '0 requests' in bullets[2]


def test_excludes_examples_deduplicates_and_preserves_uncertain_outcomes():
    detection=row('1','detected:scan_arp')
    bullets=consumer_digest([detection,detection,row('2','quarantine'),
        row('3','restore','requested'),row('4','quarantine','failed'),
        row('5','quarantine','would_have'),row('6','quarantine',actor='simulator'),
        row('7','restore',actor='seeded-demo')])
    assert '1 warning' in bullets[0]
    assert '2 demo/sample' in bullets[0]
    assert 'blocked 1 time' in bullets[1]
    assert 'restored 0 times' in bullets[1]
    assert '1 request' in bullets[2] and '1 failed' in bullets[2]
    assert '1 suggested' in bullets[2]
