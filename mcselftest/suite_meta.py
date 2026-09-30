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
import pathlib


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
