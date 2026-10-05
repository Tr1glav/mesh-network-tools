#!/usr/bin/env python3
"""Проверки прошивок meshcore на ПК, без железа.

Один набор проверок на все прошивки; что именно прогнать, выбирает ключ --target.

    python3 selftest.py --target fork      прошивки Heltec (meshcore-fork)
    python3 selftest.py --target tdeck     прошивка T-Deck
    python3 selftest.py --target core      только ядро протокола
    python3 selftest.py --target all       все цели подряд, каждая своим разделом

Пути по умолчанию — соседние каталоги рабочего дерева (там же, где лежит этот репозиторий):
`../mesh-network-core`, `../meshcore-fork`, `../tdeck`. Перебить можно ключами --core и
--root или переменными окружения MESHCORE_CORE и MESHCORE_ROOT.

Что делают проверки:
  * вырезают из исходников настоящие функции (CRC, jsonEscape, buildPingReply, rawBuildFrame,
    floodGapMs, maybeQueueRelay), собирают их хостовым компилятором с санитайзерами и гоняют
    на граничных данных — так ловятся переполнения буферов, которые на плате проявились бы
    падением;
  * сверяют связи, которые расходятся молча: тайминги против худшего случая в эфире, разметку
    страницы против её скрипта и против маршрутов сервера, признаки сборки против того, что
    читает ядро;
  * проверяют форматы, которые читает устройство: маркер платы в образе, .otaz, пакет .tapp,
    шапку ELF.

Нужен g++; node — по желанию (без него проверка синтаксиса JS пропускается).
Выход: 0 — всё прошло, 1 — есть провалы.
"""
import argparse
import os
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from mcselftest import harness, suite_meta, targets   # noqa: E402  (после sys.path)

# Рабочее дерево: каталог, в котором лежат и этот репозиторий, и проверяемые. Ядро
# подключено к прошивкам как symlink://../mesh-network-core, поэтому «рядом» — это не
# соглашение ради красоты, а то, как собирается прошивка.
TREE = HERE.parent


def resolve(name, args):
    core = pathlib.Path(args.core or os.environ.get("MESHCORE_CORE")
                        or (TREE / "mesh-network-core"))
    if name == "core":
        root = core
    else:
        root = pathlib.Path(args.root or os.environ.get("MESHCORE_ROOT")
                            or targets.default_root(name, TREE))
    return root, core


def run_target(name, args):
    root, core = resolve(name, args)
    ctx = harness.Ctx(root, core, name, tree=TREE)

    # Ядро на месте? Половина проверок вырезает функции из него, и без него они не
    # «пропускаются», а валят запуск. Тихо урезанный selftest — это ровно то, из-за чего
    # сборка в CI оставалась красной, ни на что не жалуясь.
    ok = (core / "src" / "crypto.cpp").is_file()
    ctx.check("ядро протокола найдено (%s)" % core, ok,
              "нет исходников ядра — задайте путь ключом --core или MESHCORE_CORE")
    if not ok:
        return ctx.failures

    if name != "core" and not root.is_dir():
        ctx.check("прошивка найдена (%s)" % root, False,
                  "нет каталога прошивки — задайте путь ключом --root или MESHCORE_ROOT")
        return ctx.failures

    targets.TARGETS[name][1](ctx)
    return ctx.failures


def main():
    names = list(targets.TARGETS)
    ap = argparse.ArgumentParser(
        description="Проверки прошивок meshcore на ПК",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="цели:\n" + "\n".join(
            "  %-7s %s" % (n, targets.TARGETS[n][2]) for n in names) +
        "\n  all     все цели подряд")
    ap.add_argument("--target", "-t", default="fork", choices=names + ["all"],
                    help="что проверять (по умолчанию fork)")
    ap.add_argument("--root", help="каталог проверяемой прошивки")
    ap.add_argument("--core", help="каталог ядра mesh-network-core")
    args = ap.parse_args()

    if args.target == "all" and (args.root or args.core):
        # --root для нескольких целей не имеет смысла: у каждой он свой.
        if args.root:
            ap.error("--root нельзя задавать вместе с --target all: у каждой цели свой каталог")

    todo = names if args.target == "all" else [args.target]
    failures = []

    # Сначала — проверки самого набора проверок: не потерялась ли по дороге к запуску
    # написанная проверка и на месте ли обёртки в прошивках. Идут один раз, а не на каждую
    # цель: они про этот репозиторий, а не про прошивку.
    meta = harness.Ctx(HERE, HERE, "meta", tree=TREE)
    suite_meta.wiring_test(meta)
    suite_meta.shims_test(meta, TREE)
    suite_meta.solo_tree_test(meta, TREE)
    suite_meta.ci_present_test(meta, TREE)
    suite_meta.no_secrets_test(meta, TREE)
    suite_meta.pipeline_test(meta, TREE)
    failures += ["набор проверок: %s" % f for f in meta.failures]

    for i, name in enumerate(todo):
        if len(todo) > 1:
            print(("\n" if i else "") + "=" * 62)
            print("ЦЕЛЬ: %s — %s" % (name, targets.TARGETS[name][2]))
            print("=" * 62)
        failures += ["%s: %s" % (name, f) for f in run_target(name, args)]

    print()
    if failures:
        print("ПРОВАЛЕНО: " + ", ".join(failures))
        sys.exit(1)
    print("все проверки прошли")


if __name__ == "__main__":
    main()
