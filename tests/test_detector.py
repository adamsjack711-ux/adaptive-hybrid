import json

from detector import Advisory, Detector


def poll_lattice(detector, path, samples):
    path.write_text(json.dumps([
        {"assumption": "lattice", "type": source, "confidence": confidence}
        for source, confidence in samples
    ]))
    return detector.poll(path)


def test_detector_counts_repeated_reports_as_one_source(tmp_path):
    detector = Detector()
    signals = tmp_path / "signals.json"
    reports = [("paper", .5), ("paper", 1)]

    assert poll_lattice(detector, signals, reports) == [Advisory(1, "lattice", "watch", .4, ("paper",))]
    assert poll_lattice(detector, signals, reversed(reports)) == []
    assert poll_lattice(detector, signals, reports + [("quantum", 1)]) == [
        Advisory(2, "lattice", "warn", .75, ("paper", "quantum")),
    ]


def test_detector_swap_threshold_hysteresis_and_cleared_snapshot(tmp_path):
    detector = Detector()
    signals = tmp_path / "signals.json"
    corroborators = ("paper", "quantum")

    assert poll_lattice(detector, signals, [("paper", 1), ("quantum", 1), ("anomaly", .2)]) == [
        Advisory(1, "lattice", "swap", .8, corroborators),
    ]
    assert poll_lattice(detector, signals, [("paper", .5), ("quantum", 1)]) == []  # Score .55 holds swap.
    assert poll_lattice(detector, signals, [("paper", .4975), ("quantum", 1)]) == [
        Advisory(2, "lattice", "warn", .549, corroborators),
    ]
    assert poll_lattice(detector, signals, []) == [Advisory(3, "lattice", "normal", 0.0, ())]
