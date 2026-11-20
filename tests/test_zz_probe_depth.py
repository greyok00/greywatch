from appfw.ruleset import AppRule, render_ruleset

FEED_IPS = {"firehol-l1": {"203.0.113.7", "198.51.100.23"},
            "urlhaus": {"192.0.2.66"}}

def test_probe_with_feeds():
    deep = AppRule(scope="/user.slice/user-1000.slice/user@1000.service"
                         "/app.slice/app-gnome-firefox@4123.scope",
                   basename="app-gnome-firefox@4123.scope",
                   verdict="allow", note="")
    text = render_ruleset([deep], FEED_IPS, catch=True)
    print("WITH-FEEDS SOCKET:", [l for l in text.splitlines() if "socket" in l])
    assert "socket cgroupv2 level 5" in text
