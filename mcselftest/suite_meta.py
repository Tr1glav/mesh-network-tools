"""Проверки самого набора проверок.

Появились вместе с переездом проверок из форков в этот репозиторий. Переезд создал новый
способ потерять проверку молча: раньше функция вызывалась из блока `if __name__` того же
файла, где была написана, и забыть про неё было трудно — она стояла строкой ниже. Теперь
функции лежат в suite_*.py, а вызываются из targets.py, то есть из другого файла. Написал
проверку, не дописал вызов — прогон зелёный, проверки нет, и заметить это можно только
сравнив вывод с прошлым.

Поэтому здесь проверяется не прошивка, а связность: каждая написанная проверка обязана быть
кем-то вызвана, и каждая цель обязана быть запускаемой.
"""
import ast
import contextlib
import io
import pathlib
import re
import tempfile

from . import harness, suite_core


def _defined_tests(path):
    """Имена функций-проверок, определённых в модуле: всё, что кончается на _test."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {n.name for n in tree.body
            if isinstance(n, ast.FunctionDef) and n.name.endswith("_test")}


def _called_names(path):
    """Имена, которые в модуле вызывают: и напрямую, и через `модуль.имя()`."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Name):
                out.add(f.id)
            elif isinstance(f, ast.Attribute):
                out.add(f.attr)
    return out


def ci_present_test(ctx, tree):
    """У каждого репозитория есть свой CI.

    У ядра и у этого репозитория своего CI не было вовсе — при том что в ядре протокол, крипто
    и разбор кадров, а здесь сами проверки. Правка в любом из двух всплывала только на
    следующей сборке прошивки: её workflow берёт проверки по `tools.ref`, то есть правка здесь
    меняет результат чужой сборки, которую никто не трогал.

    Проверка намеренно смотрит на все четыре репозитория: заводить CI по одному легко, а
    забыть про четвёртый — ещё легче."""
    want = {
        "mesh-network-core":  "проверки ядра: суть репозитория — протокол, крипто, кадры",
        "mesh-network-tools": "проверки самих проверок: сломанный набор роняет чужие сборки",
        "meshcore-fork":      "сборка прошивок Heltec и релиз",
        "tdeck":              "сборка прошивки T-Deck и релиз",
    }
    seen = 0
    for sub, why in want.items():
        repo = pathlib.Path(tree) / sub
        if not repo.is_dir():
            continue
        seen += 1
        wf = repo / ".github" / "workflows"
        files = sorted(wf.glob("*.yml")) + sorted(wf.glob("*.yaml")) if wf.is_dir() else []
        ctx.check("у %s есть workflow" % sub, bool(files),
                  "нет ни одного файла в .github/workflows — %s" % why)
        for f in files:
            txt = f.read_text(encoding="utf-8")
            ctx.check("%s/%s запускается на push" % (sub, f.name),
                      re.search(r"^\s*push\s*:", txt, re.M) is not None,
                      "workflow есть, но на push не запускается — значит не запускается никогда")
    if not seen:
        ctx.note("SKIP ci_present_test: репозиториев рядом нет")


def wiring_test(ctx, pkg=None):
    """Ни одна написанная проверка не потерялась по дороге к запуску."""
    pkg = pathlib.Path(pkg) if pkg else pathlib.Path(__file__).resolve().parent
    suites = sorted(pkg.glob("suite_*.py"))
    ctx.check("наборы проверок на месте", len(suites) >= 3,
              "найдено файлов suite_*.py: %d" % len(suites))

    targets_py = pkg / "targets.py"
    ctx.check("описание целей на месте", targets_py.is_file(), str(targets_py))
    if not targets_py.is_file():
        return

    # Вызвать проверку может и targets.py, и другая проверка: страница форка разбирается
    # цепочкой (page_js_test -> page_ids_test -> endpoints_test, info_fields_test), и это
    # законно — текст страницы читается один раз и передаётся дальше.
    called = _called_names(targets_py)
    for s in suites:
        called |= _called_names(s)
    # ...и сам запускатель: проверки этого файла (suite_meta) зовёт он, а не цель — они про
    # набор проверок, а не про прошивку, и идут один раз на прогон.
    runner = pkg.parent / "selftest.py"
    if runner.is_file():
        called |= _called_names(runner)

    orphans = []
    for s in suites:
        for name in sorted(_defined_tests(s)):
            if name not in called:
                orphans.append("%s.%s" % (s.stem, name))
    ctx.check("каждая написанная проверка кем-то вызывается", not orphans,
              "никто не зовёт: " + ", ".join(orphans))

    # Обратная сторона: цель объявлена, а запускать нечего.
    from . import targets
    bad = [n for n, (_, fn, _) in targets.TARGETS.items() if not callable(fn)]
    ctx.check("у каждой цели есть что запускать", not bad, ", ".join(bad))


def shims_test(ctx, tree):
    """Обёртки в прошивках зовут общий запускатель, и каждая — свою цель.

    Обёртка маленькая, и именно поэтому её легко сломать незаметно: перепутанная цель даёт
    зелёный прогон не тех проверок, а потерянная обёртка — привычную команду, которая больше
    ничего не проверяет.
    """
    tree = pathlib.Path(tree)
    for sub, target in (("meshcore-fork", "fork"), ("tdeck", "tdeck")):
        shim = tree / sub / "scripts" / "selftest.py"
        if not shim.is_dir() and not shim.is_file():
            continue
        txt = shim.read_text(encoding="utf-8")
        ctx.check("обёртка %s зовёт общий запускатель" % sub,
                  "mesh-network-tools" in txt and "selftest.py" in txt,
                  "%s не ссылается на репозиторий проверок" % shim)
        ctx.check("обёртка %s запускает цель %s" % (sub, target),
                  '"--target", "%s"' % target in txt,
                  "в %s не найдена цель %s" % (shim, target))


def solo_tree_test(ctx, tree):
    """Проверка ядра не имеет права читать прошивку, которой рядом нет.

    CI клонирует ОДНУ прошивку рядом с ядром — ту, чью ветку и собрали. Второй прошивки на
    диске нет, и проверка ядра, читающая её напрямую, падает там, где у разработчика всё
    зелёное: у него рядом лежат все три репозитория.

    Именно так и вышло: `weak_hooks_test` и `ota_screen_progress_test` требовали обе прошивки
    безусловно, локально проходили, а релизная сборка `meshcore-fork` упала на шаге
    «Проверки на ПК». Правило записано в `targets.py` («ни одной прошивки рядом может и не
    быть»), но чем оно обеспечено — ничем: нарушение видно только в CI.

    Здесь оно обеспечивается запуском: поднимается временное дерево, где лежат ядро и РОВНО
    ОДНА прошивка, и кросс-репозиторные проверки ядра прогоняются по нему. Падать не на чему —
    второй прошивки физически нет.
    """
    tree = pathlib.Path(tree)
    for sub in ("meshcore-fork", "tdeck"):
        src = tree / sub
        if not src.is_dir():
            continue  # прошивки нет рядом — проверять нечего
        with tempfile.TemporaryDirectory(prefix="solo-") as tmp:
            root = pathlib.Path(tmp)
            (root / sub).symlink_to(src, target_is_directory=True)
            # Ядро кладём рядом ССЫЛКОЙ: корень дерева указывает на каталог ядра (как в
            # selftest.py), а копия в 40 МБ ради проверки ни к чему.
            (root / "mesh-network-core").symlink_to(tree / "mesh-network-core",
                                                     target_is_directory=True)
            solo = harness.Ctx(root / sub, tree / "mesh-network-core", "fork", tree=root)
            # Тишина: прогон внутри проверки не должен выглядеть как ещё одна проверка.
            buf = io.StringIO()
            try:
                with contextlib.redirect_stdout(buf):
                    suite_core.weak_hooks_test(solo)
                    suite_core.ota_screen_progress_test(solo)
                    suite_core.any_session_test(solo)
            except Exception as e:  # noqa: BLE001 — падение здесь и есть ложь проверки
                ctx.check("проверки ядра живут без второй прошивки (%s)" % sub, False,
                          "%s: %s: %s" % (type(e).__name__, e,
                                          (buf.getvalue() or "").strip()[-400:]))
                continue
            ctx.check("проверки ядра живут без второй прошивки (%s)" % sub,
                      not solo.failures,
                      "упали без второй прошивки на диске: %s — по правилу из targets.py "
                      "молчание честнее выдуманного «OK»"
                      % ", ".join(solo.failures[:6]))
