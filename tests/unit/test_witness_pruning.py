"""Restore-witness pruning audit (ADR 0010, "Pruning"): who may delete which records, and that no pruning schedule,
listing defect or interruption can remove the record that holds the high-water mark.

These run against the local directory witness and an in-memory model of listings. They establish the algorithm's
invariant; they say nothing about a production object store's durability or listing consistency (still unverified).
"""
from __future__ import annotations

import random
import threading

import pytest

from axiom.jobs.witness import KEEP, FileWitness, _parse, prune_candidates


def names(d):
    return sorted(p.name for p in d.iterdir() if _parse(p.name) is not None)


def test_exact_worker_identity_with_suffix_and_prefix_lookalikes(tmp_path):
    ids = ["w1", "a-w1", "w1-x", "1", "w"]
    ws = {i: FileWitness(tmp_path, i) for i in ids}
    n = 0
    for _ in range(6):
        for i in ids:
            n += 1
            ws[i].advance(n)
    present = names(tmp_path)
    for i in ids:
        own = [x for x in present if x[21:] == i]
        assert len(own) == KEEP, (i, own)       # each kept exactly its own newest KEEP; nobody pruned another
    assert ws["w1"].high_water() == n


def test_candidates_are_only_own_records_below_the_newest_keep():
    listing = [f"{v:020d}-{w}" for v, w in [(1, "a"), (2, "a-b"), (3, "a"), (4, "a"), (5, "b"), (6, "a"), (9, "a")]]
    assert prune_candidates(listing, "a") == [f"{1:020d}-a", f"{3:020d}-a"]
    assert prune_candidates(listing, "b") == []
    assert prune_candidates(listing, "a", keep=0) == []          # a misconfigured KEEP never deletes everything
    assert prune_candidates(["_probe/x", "junk", f"{7:020d}"], "a") == []


@pytest.mark.parametrize("seed", range(40))
def test_no_listing_defect_or_interruption_can_remove_the_maximum(seed):
    """Model: workers (some sharing an ID) write increasing watermarks and prune from a listing that may be stale,
    partial (pagination cut short) or missing their own newest write; deletes may be interrupted part-way."""
    rng = random.Random(seed)
    store: set[str] = set()
    snapshots: list[set[str]] = [set()]
    workers = ["w1", "a-w1", "w1", "b", "c"][: rng.randint(2, 5)]
    written_max = 0
    for v in range(1, 120):
        w = rng.choice(workers)
        name = f"{v:020d}-{w}"
        store.add(name)
        written_max = v
        snapshots.append(set(store))
        mode = rng.random()
        if mode < 0.3:
            listing = set(rng.choice(snapshots))                     # stale listing from any earlier moment
        elif mode < 0.6:
            listing = set(sorted(store)[: rng.randint(0, len(store))])   # paginated listing cut short
        else:
            listing = {x for x in store if rng.random() < 0.7}       # arbitrary partial listing
        listing &= store | set().union(*snapshots[-3:])              # a listing only names records that existed
        cands = prune_candidates(sorted(listing), w)
        stop = rng.randint(0, len(cands))                            # interrupted after `stop` deletes
        for c in cands[:stop]:
            store.discard(c)
        assert max(_parse(x) for x in store) == written_max          # the mark never decreases
    by_owner: dict[str, list[int]] = {}
    for x in store:
        by_owner.setdefault(x[21:], []).append(_parse(x))
    assert written_max in by_owner[max(store, key=_parse)[21:]]


def test_concurrent_writers_and_pruners_on_one_directory(tmp_path):
    counter = iter(range(1, 100_000))
    lock = threading.Lock()
    ids = ["w1", "a-w1", "dup", "dup", "x"]
    highest = [0]
    samples: list[int] = []
    stop = threading.Event()

    def writer(i):
        w = FileWitness(tmp_path, i)
        for _ in range(150):
            with lock:
                v = next(counter)
                highest[0] = max(highest[0], v)
            w.advance(v)

    def reader():
        r = FileWitness(tmp_path, "reader")
        last = 0
        while not stop.is_set():
            hw = r.high_water() or 0
            assert hw >= last                     # a reader never sees the mark go backwards
            last = hw
            samples.append(hw)

    rt = threading.Thread(target=reader)
    rt.start()
    threads = [threading.Thread(target=writer, args=(i,)) for i in ids]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    stop.set()
    rt.join()
    assert FileWitness(tmp_path, "check").high_water() == highest[0]
    present = names(tmp_path)
    for i in set(ids):
        assert len([x for x in present if x[21:] == i]) >= KEEP
    assert samples


def test_interrupted_prune_leaves_extra_records_and_a_correct_mark(tmp_path, monkeypatch):
    w = FileWitness(tmp_path, "w")
    for v in range(1, 5):
        w.advance(v)
    calls = {"n": 0}
    real = FileWitness._delete

    def flaky(self, name):
        calls["n"] += 1
        if calls["n"] > 1:
            raise OSError("crash mid-prune")
        real(self, name)
    monkeypatch.setattr(FileWitness, "_delete", flaky)
    for v in range(5, 9):
        w.advance(v)                              # pruning fails part-way; writes still succeed
    assert w.high_water() == 8 and len(names(tmp_path)) > KEEP
    monkeypatch.setattr(FileWitness, "_delete", real)
    w.advance(9)
    assert w.high_water() == 9 and len(names(tmp_path)) == KEEP
