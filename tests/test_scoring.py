import datetime as dt
import unittest

from infocon import config, scoring

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 11, 13, 12, tzinfo=UTC)


def comp(cid, score):
    return {"id": cid, "label": cid, "weight": config.WEIGHTS[cid], "score": score, "signals": [], "sources": []}


class Curve(unittest.TestCase):
    def test_interp_clamps_and_interpolates(self):
        c = [(0, 20), (2, 40)]
        self.assertEqual(scoring.interp(c, -5), 20)
        self.assertEqual(scoring.interp(c, 1), 30)
        self.assertEqual(scoring.interp(c, 9), 40)

    def test_normal_day_scores_twenty(self):
        s = scoring.signal("x", "x", 100, [90, 95, 100, 100, 105, 110, 100, 100], "things")
        self.assertAlmostEqual(s["score"], 20, delta=1)

    def test_flat_baseline_does_not_explode(self):
        # 3% above a perfectly flat baseline must stay unremarkable
        s = scoring.signal("x", "x", 103, [100] * 14, "things")
        self.assertLess(s["score"], 30)

    def test_spike_scores_high_and_log_scale_tames_heavy_tails(self):
        base = [1000, 1200, 900, 1100, 1000, 950, 1050, 1000, 980, 1020]
        lin = scoring.signal("x", "x", 6000, base, "things")
        log = scoring.signal("x", "x", 6000, base, "things", log=True, floor_rel=0.25)
        self.assertGreaterEqual(lin["score"], 95)
        self.assertTrue(55 <= log["score"] < lin["score"])

    def test_too_little_history_gives_no_signal(self):
        self.assertIsNone(scoring.signal("x", "x", 5, [1, 2, 3], "things"))


class Composite(unittest.TestCase):
    def quiet(self, **over):
        scores = dict.fromkeys(config.WEIGHTS, 22)
        scores.update(over)
        return {k: comp(k, v) for k, v in scores.items()}

    def test_quiet_is_green(self):
        score, cov = scoring.composite(self.quiet())
        self.assertEqual(scoring.level_for(score), "GREEN")
        self.assertEqual(cov, 1.0)

    def test_one_screaming_component_is_not_averaged_away(self):
        score, _ = scoring.composite(self.quiet(scanning=95))
        self.assertEqual(scoring.level_for(score), "ORANGE")

    def test_red_needs_corroboration(self):
        one, _ = scoring.composite(self.quiet(scanning=100))
        two, _ = scoring.composite(self.quiet(scanning=100, exploitation=100))
        self.assertNotEqual(scoring.level_for(one), "RED")
        self.assertEqual(scoring.level_for(two), "RED")

    def test_smallest_component_alone_cannot_reach_red(self):
        score, _ = scoring.composite(self.quiet(ransomware=100))
        self.assertIn(scoring.level_for(score), ("YELLOW", "ORANGE"))

    def test_missing_components_renormalise(self):
        comps = self.quiet()
        comps["scanning"] = None
        score, cov = scoring.composite(comps)
        self.assertAlmostEqual(score, 22, delta=0.1)
        self.assertEqual(cov, 0.8)


class Hysteresis(unittest.TestCase):
    def test_escalates_immediately(self):
        st = scoring.apply_hysteresis(20, 1, {}, NOW)
        st = scoring.apply_hysteresis(60, 1, st, NOW + dt.timedelta(minutes=30))
        self.assertEqual(st["level"], "ORANGE")

    def test_holds_before_stepping_down(self):
        st = scoring.apply_hysteresis(60, 1, {}, NOW)
        st = scoring.apply_hysteresis(20, 1, st, NOW + dt.timedelta(hours=1))
        self.assertEqual(st["level"], "ORANGE")
        st = scoring.apply_hysteresis(20, 1, st, NOW + dt.timedelta(hours=1 + config.HOLD_HOURS))
        self.assertEqual(st["level"], "GREEN")

    def test_bounce_back_resets_the_clock(self):
        st = scoring.apply_hysteresis(60, 1, {}, NOW)
        st = scoring.apply_hysteresis(20, 1, st, NOW + dt.timedelta(hours=1))
        st = scoring.apply_hysteresis(54, 1, st, NOW + dt.timedelta(hours=2))  # inside the margin
        self.assertIsNone(st["below_since"])
        st = scoring.apply_hysteresis(20, 1, st, NOW + dt.timedelta(hours=3 + config.HOLD_HOURS - 2))
        self.assertEqual(st["level"], "ORANGE")

    def test_blind_run_keeps_previous_level(self):
        st = scoring.apply_hysteresis(60, 1, {}, NOW)
        st = scoring.apply_hysteresis(10, 0.3, st, NOW + dt.timedelta(days=2))
        self.assertEqual(st["level"], "ORANGE")
        self.assertTrue(st["degraded"])


class Outages(unittest.TestCase):
    def test_single_source_alerts_are_ignored(self):
        rows = [["CN", 700000, "gtr"], ["FI", 27000, "gtr"], ["VE", 15000, "bgp,ping-slash24"]]
        self.assertEqual(scoring.corroborated(rows), ["VE"])

    def test_glitching_source_is_discounted(self):
        rows = [[f"C{i}", 9000, "ping-slash24"] for i in range(150)]
        rows += [[f"B{i}", 9000, "bgp,ping-slash24"] for i in range(5)] + [["XX", 9000, "bgp,gtr"]]
        self.assertEqual(scoring.corroborated(rows), ["XX"])


def incident(provider, tier, points, started, ended=None):
    iso = lambda h: None if h is None else (NOW - dt.timedelta(hours=h)).isoformat()
    return {"provider": provider, "tier": tier, "points": points, "impact": "major", "title": f"{provider} trouble",
            "started": iso(started), "ended": iso(ended), "url": ""}


class BigServices(unittest.TestCase):
    """The reason this exists: when Outlook is down for everyone, say so."""

    def level(self, incidents, hn=None, live=True):
        ctx = {"now": NOW, "today": NOW.date(), "day": NOW.date(), "live": live}
        infra = scoring.infrastructure(None, {"incidents": incidents, "checked": ["x"]}, hn, ctx)
        comps = {k: comp(k, 22) for k in config.WEIGHTS}
        comps["infrastructure"] = infra
        score, _ = scoring.composite(comps)
        return scoring.level_for(score), infra

    def test_major_outage_at_a_tier2_provider_is_at_least_yellow(self):
        level, infra = self.level([incident("Microsoft 365", 2, 3, started=2)])
        self.assertEqual(level, "YELLOW")
        self.assertIn("ongoing", infra["signals"][0]["text"])

    def test_it_still_counts_for_hours_after_it_is_fixed(self):
        level, infra = self.level([incident("Microsoft 365", 2, 3, started=9, ended=4)])
        self.assertEqual(level, "YELLOW")
        self.assertIn("resolved 4h ago", infra["signals"][0]["text"])
        level, _ = self.level([incident("Microsoft 365", 2, 3, started=60, ended=30)])
        self.assertEqual(level, "GREEN")

    def test_critical_outage_at_a_tier2_provider_reaches_orange_with_chatter(self):
        hn = {"daily": {}, "recent": [{"kind": "outage", "points": 1500, "title": "AWS is down", "t": 0, "id": "1"}]}
        level, _ = self.level([incident("AWS", 2, 6, started=1)], hn)
        self.assertEqual(level, "ORANGE")

    def test_routine_noise_stays_green(self):
        noise = [incident("Cloudflare", 2, 1, started=h) for h in (1, 3, 5, 8)]
        noise += [incident("GitHub", 1, 3, started=2), incident("Zoom", 1, 1, started=6), incident("OpenAI", 1, 1, started=4)]
        level, infra = self.level(noise)
        self.assertEqual(level, "GREEN")
        self.assertLess(infra["signals"][0]["score"], 35)

    def test_incident_left_open_for_weeks_fades(self):
        self.assertEqual(scoring.incident_weight(incident("AWS", 2, 6, started=1), NOW), 1.0)
        self.assertLessEqual(scoring.incident_weight(incident("AWS", 2, 6, started=24 * 90), NOW), 0.1)
        self.assertEqual(scoring.incident_weight(incident("AWS", 2, 6, started=-5), NOW), 0.0)  # not started yet

    def test_replay_counts_anything_open_that_day(self):
        level, _ = self.level([incident("Google Cloud", 2, 3, started=20, ended=18)], live=False)
        self.assertEqual(level, "YELLOW")


class StatusCard(unittest.TestCase):
    def status(self, **kw):
        base = {"level": "YELLOW", "score": 48.9, "degraded": False, "generated": "2026-11-13T22:15:00+00:00",
                "drivers": [{"component": "infrastructure", "label": "Big-service incidents", "score": 74.5,
                             "text": "Microsoft 365: users can't sign in <major> & " + "more words " * 30},
                            {"component": "chatter", "label": "Security headlines", "text": "x", "score": 50}]}
        return {**base, **kw}

    def test_card_is_valid_svg_with_reason(self):
        from xml.dom import minidom
        from infocon import render
        svg = render.card(self.status())
        minidom.parseString(svg)  # escaping holds for <, & and quotes
        self.assertIn("YELLOW", svg)
        self.assertIn("Microsoft 365", svg)
        self.assertIn("Also: Security headlines", svg)
        self.assertIn("…", svg)  # long reasons are cut, not overflowed

    def test_card_without_drivers_or_score(self):
        from xml.dom import minidom
        from infocon import render
        minidom.parseString(render.card(self.status(level="GREEN", drivers=[])))
        held = render.card(self.status(degraded=True, score=None))
        minidom.parseString(held)
        self.assertIn("level is being held", held)


if __name__ == "__main__":
    unittest.main()
