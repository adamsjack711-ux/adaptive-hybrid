"""Bounded, repeatable JetStream load and crash test for policy recovery."""

import argparse
import asyncio
from contextlib import ExitStack
import json
from math import ceil
from pathlib import Path
import random
from statistics import median
from tempfile import TemporaryDirectory
from time import perf_counter

from combiner import STREAM, SUBJECTS, load_nats
from detector import Advisory, SLH, Voter
from handshake import require_kems
from verification.broker import broker
from verification.recovery_stress import make_nodes, traffic
from wire import encode_certificate


def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[ceil((len(ordered) - 1) * fraction)]


async def exercise(instance, directory, roster, verifier, certificates, *, count, epochs,
                   gap_every, restart_every_gaps, seed):
    nats, api = load_nats()
    nc = await nats.connect(instance.url, allow_reconnect=False)
    js = nc.jetstream()
    await js.add_stream(name=STREAM, subjects=SUBJECTS, storage=api.StorageType.FILE,
                        max_age=86400)
    nodes = make_nodes(directory, roster, verifier, instance.url, count)
    rng = random.Random(seed)
    previous = {}
    durations, recovery_durations = [], []
    packets = gaps = restarts = boundaries = published = 0

    async def connect_all():
        await asyncio.gather(*(node.connect() for node in nodes))

    async def publish(epoch, recipients):
        nonlocal published
        advisory, votes = certificates[epoch]
        ack = await js.publish("advisories." + advisory.assumption,
                               encode_certificate(advisory, votes), stream=STREAM)
        published += 1
        await asyncio.gather(*(node.through(ack.seq) for node in recipients))
        return ack.seq

    async def restart():
        nonlocal nc, js, nodes, restarts
        await asyncio.gather(*(node.disconnect() for node in nodes))
        await nc.close()
        old_pid = instance.proc.pid
        instance.restart()
        if instance.proc.pid == old_pid:
            raise AssertionError("broker did not restart")
        nc = await nats.connect(instance.url, allow_reconnect=False)
        js = nc.jetstream()
        nodes = make_nodes(directory, roster, verifier, instance.url, count)
        if any(peer.key is not None for node in nodes for peer in node.pair):
            raise AssertionError("restored peer retained a traffic key")
        await connect_all()
        restarts += 1

    try:
        await connect_all()
        started = perf_counter()
        epoch = 1
        while epoch <= epochs:
            step_started = perf_counter()
            if epoch > 1 and epoch < epochs and epoch % gap_every == 0:
                gaps += 1
                held = set(rng.sample(range(count), max(1, count // 4)))
                online = [node for i, node in enumerate(nodes) if i not in held]
                offline = [node for i, node in enumerate(nodes) if i in held]
                await asyncio.gather(*(node.disconnect() for node in offline))
                await publish(epoch + 1, online)
                if any(node.ready_for(epoch + 1) for node in nodes):
                    raise AssertionError("future epoch activated before missing history")
                if gaps % restart_every_gaps == 0:
                    await restart()
                    online, offline = nodes, []
                await publish(epoch, online)
                if offline:
                    await asyncio.gather(*(node.connect() for node in offline))
                    target = (await js.stream_info(STREAM)).state.last_seq
                    await asyncio.gather(*(node.through(target) for node in offline))
                if any(not node.ready_for(epoch + 1) for node in nodes):
                    raise AssertionError(f"nodes failed to recover epoch {epoch + 1}")
                traffic(nodes, epoch + 1, previous)
                packets += count * 2
                boundaries += 1
                recovery_durations.append(perf_counter() - step_started)
                epoch += 2
            else:
                await publish(epoch, nodes)
                if any(not node.ready_for(epoch) for node in nodes):
                    raise AssertionError(f"nodes failed to reach epoch {epoch}")
                traffic(nodes, epoch, previous)
                packets += count * 2
                boundaries += 1
                epoch += 1
            durations.append(perf_counter() - step_started)
        elapsed = perf_counter() - started
        if any(node.cursor != published or node.deferred for node in nodes):
            raise AssertionError("cursor or deferred certificate remained after catch-up")
        return {
            "nodes": count, "epochs": epochs, "seed": seed, "gap_every": gap_every,
            "restart_every_gaps": restart_every_gaps, "signed_messages": published,
            "boundaries": boundaries, "gap_recoveries": gaps, "broker_restarts": restarts,
            "encrypted_packets": packets, "elapsed_s": round(elapsed, 3),
            "deliveries_per_s": round(count * published / elapsed, 1),
            "step_median_ms": round(median(durations) * 1000, 1),
            "step_p95_ms": round(percentile(durations, .95) * 1000, 1),
            "recovery_max_ms": round(max(recovery_durations, default=0) * 1000, 1),
        }
    finally:
        await asyncio.gather(*(node.disconnect() for node in nodes))
        await nc.close()


def main():
    if not __debug__:
        raise RuntimeError("run without -O so assertions are enabled")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nodes", type=int, default=5)
    parser.add_argument("--epochs", type=int, default=30)
    parser.add_argument("--gap-every", type=int, default=7)
    parser.add_argument("--restart-every-gaps", type=int, default=2)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args()
    if not 2 <= args.nodes <= 100 or not 3 <= args.epochs <= 1000:
        parser.error("nodes must be 2..100 and epochs 3..1000")
    if args.gap_every < 2 or args.restart_every_gaps < 1 or args.timeout < 1:
        parser.error("gap-every must be at least 2; restart-every-gaps and timeout must be positive")
    oqs = require_kems()
    if SLH not in oqs.get_enabled_sig_mechanisms():
        raise RuntimeError(f"Enable {SLH} in liboqs")
    with TemporaryDirectory(prefix="adaptive-load-") as tmp, ExitStack() as stack, broker() as instance:
        directory = Path(tmp)
        voters = [Voter(str(i), oqs, stack, directory / f"voter-{i}.state") for i in range(3)]
        roster = {v.name: v.public for v in voters}
        verifier = stack.enter_context(oqs.Signature(SLH))
        certificates = {}
        for epoch in range(1, args.epochs + 1):
            tier = "swap" if epoch % 4 == 0 else "normal"
            advisory = Advisory(epoch, "lattice", tier, .85 if tier == "swap" else 0,
                                ("paper", "quantum") if tier == "swap" else ())
            certificates[epoch] = advisory, [v.vote(advisory) for v in voters]
        result = asyncio.run(asyncio.wait_for(exercise(
            instance, directory, roster, verifier, certificates, count=args.nodes,
            epochs=args.epochs, gap_every=args.gap_every,
            restart_every_gaps=args.restart_every_gaps, seed=args.seed), timeout=args.timeout))
    print("PASS " + json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
