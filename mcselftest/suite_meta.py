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
import json
import pathlib
import re
import subprocess
import sys
import tempfile

from . import harness, suite_core


def _defined_tests(path):
    """Имена функций-проверок, определённых в модуле: всё, что кончается на _test."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {n.name for n in tree.body if isinstance(n, ast.FunctionDef) and n.name.endswith("_test")}


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


def _snapshot_ref(repo):
    """Снимок по пину или живая копия — см. harness.snapshot_ref.

    Обёртка осталась затем, что вопрос «снимок или рабочая копия» задают и проверки ядра
    (номер версии в library.json), и реализация должна быть одна.
    """
    return harness.snapshot_ref(repo)


def _job_block(txt, name):
    """Текст одного задания workflow, без комментариев. Без разбора YAML — намеренно.

    PyYAML в окружении CI не гарантирован: setup-python ставит чистый интерпретатор, а
    platformio его за собой не тянет. Поэтому ci_present_test обходится регулярками, и здесь
    тот же приём: задание — это блок от строки «<имя>:» до следующей строки с тем же
    отступом. Комментарии вырезаются, иначе упоминание в пояснении сошло бы за код — а
    проверка ниже как раз требует, чтобы `core.ref` в задании НЕ читался, хотя в
    комментарии рядом он назван.
    """
    indent, out = None, []
    for ln in txt.splitlines():
        if indent is None:
            m = re.match(r"^(\s*)%s\s*:\s*$" % re.escape(name), ln)
            if m:
                indent = len(m.group(1))
            continue
        if ln.strip() and not ln.startswith(" " * (indent + 1)):
            break
        out.append(re.sub(r"#.*$", "", ln))
    return "\n".join(out) if indent is not None else None


def ci_present_test(ctx, tree):
    """У каждого репозитория есть свой CI.

    У ядра и у этого репозитория своего CI не было вовсе — при том что в ядре протокол, крипто
    и разбор кадров, а здесь сами проверки. Правка в любом из двух всплывала только на
    следующей сборке прошивки: её workflow берёт проверки по `tools.ref`, то есть правка здесь
    меняет результат чужой сборки, которую никто не трогал.

    Проверка намеренно смотрит на все четыре репозитория: заводить CI по одному легко, а
    забыть про четвёртый — ещё легче."""
    want = {
        "mesh-network-core": "проверки ядра: суть репозитория — протокол, крипто, кадры",
        "mesh-network-tools": "проверки самих проверок: сломанный набор роняет чужие сборки",
        "meshcore-fork": "сборка прошивок Heltec и релиз",
        "tdeck": "сборка прошивки T-Deck и релиз",
    }
    seen = 0
    for sub, why in want.items():
        repo = pathlib.Path(tree) / sub
        if not harness.repo_present(pathlib.Path(tree), sub):
            continue
        seen += 1
        snap = _snapshot_ref(repo)
        if snap:
            ctx.note("SKIP %s: выложен по пину (%s), а не рабочей копией — свой CI проверяется по ветке" % (sub, snap))
            continue
        wf = repo / ".github" / "workflows"
        files = sorted(wf.glob("*.yml")) + sorted(wf.glob("*.yaml")) if wf.is_dir() else []
        ctx.check("у %s есть workflow" % sub, bool(files), "нет ни одного файла в .github/workflows — %s" % why)
        for f in files:
            txt = f.read_text(encoding="utf-8")
            ctx.check(
                "%s/%s запускается на push" % (sub, f.name),
                re.search(r"^\s*push\s*:", txt, re.M) is not None,
                "workflow есть, но на push не запускается — значит не запускается никогда",
            )
    if not seen:
        ctx.note("SKIP ci_present_test: репозиториев рядом нет")


def readme_present_test(ctx, tree):
    """У каждого репозитория есть README, и он не пустая заглушка.

    Правило 5 требует дополнять описания вместе с кодом, но первым описанием репозитория
    служит README — то, что человек видит, открыв его на GitHub. У `mesh-network-core` его
    не было вовсе: единственный из четырёх, где на входе не сказано ни что это, ни как
    собирается, при том что собрать его отдельно нельзя вообще (библиотека без
    `platformio.ini`), и без README это выглядит как сломанный репозиторий.

    Порог в 2000 байт выбран как «описание, а не отписка»: README из трёх строк формально
    закрывает проверку на наличие файла и не отвечает ни на один вопрос читателя. У
    существующих README размер от 3 КБ."""
    want = {
        "mesh-network-core": "библиотека без своей сборки: без README не видно, как её вообще собирать",
        "mesh-network-tools": "точка входа в проверки: что запускать и как добавить свою",
        "meshcore-fork": "прошивки Heltec: окружения, роли, выпуск",
        "tdeck": "прошивка T-Deck: окружение, приложения, выпуск",
    }
    seen = 0
    for sub, why in want.items():
        repo = pathlib.Path(tree) / sub
        if not harness.repo_present(pathlib.Path(tree), sub):
            continue
        seen += 1
        snap = _snapshot_ref(repo)
        if snap:
            ctx.note("SKIP %s: выложен по пину (%s), а не рабочей копией" % (sub, snap))
            continue
        f = repo / "README.md"
        if not ctx.check("у %s есть README.md" % sub, f.is_file(), "нет README.md — %s" % why):
            continue
        size = len(f.read_text(encoding="utf-8").encode("utf-8"))
        ctx.check(
            "README %s — описание, а не заглушка" % sub,
            size >= 2000,
            "README.md на %d байт: %s" % (size, why),
        )
    if not seen:
        ctx.note("SKIP readme_present_test: репозиториев рядом нет")


def no_secrets_test(ctx, tree):
    """Ни один репозиторий не держит у себя токен или приватный ключ.

    Токен GitHub лежит в `.env` в корне рабочего дерева. Корень сам стал репозиторием
    (публичный `mesh-network-lint`, 16.10.2026), поэтому «вне git» больше не защита: `.env`
    держится закрытым `.gitignore` корня и убран из индекса. Внутри любого из четырёх
    репозиториев такой файл попал бы в коммит, и цена ошибки — секрет в истории публичного
    репозитория, откуда его уже не убрать переписыванием.

    Проверка ищет не конкретное значение (хранить его здесь означало бы ровно то, от чего
    защищаемся), а признаки формата: префиксы токенов GitHub и шапку приватного ключа. Смотрит
    только отслеживаемые git'ом файлы: `.env` рядом с репозиторием, но вне его, — это норма."""
    # Маркеры собираются из частей намеренно: написанные целиком, они сделали бы ЭТОТ файл
    # «похожим на секрет», и проверка падала бы на себе самой — так и случилось при первом
    # прогоне. Склейка решает это без списка исключений, который пришлось бы поддерживать.
    marks = tuple("github_" + "pat_" for _ in (0,)) + (
        "gh" + "p_",
        "gh" + "o_",
        "gh" + "s_",
        "BEGIN OPENSSH PRIVATE " + "KEY",
        "BEGIN RSA PRIVATE " + "KEY",
    )
    seen = 0
    for sub in ("mesh-network-core", "mesh-network-tools", "meshcore-fork", "tdeck"):
        repo = pathlib.Path(tree) / sub
        if not (repo / ".git").exists():
            continue
        seen += 1
        r = subprocess.run(["git", "ls-files", "-z"], cwd=str(repo), capture_output=True, text=True)
        files = [f for f in r.stdout.split("\0") if f]
        bad = []
        for rel in files:
            f = repo / rel
            if not f.is_file() or f.stat().st_size > 2_000_000:
                continue
            try:
                txt = f.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for m in marks:
                if m in txt:
                    bad.append("%s (%s)" % (rel, m))
                    break
        ctx.check("%s не держит секретов в отслеживаемых файлах" % sub, not bad, "похоже на секрет: " + "; ".join(bad))
        # Правило в .gitignore — про то, как репозиторий поддерживается СЕЙЧАС, а снимок по
        # пину этого не знает: см. _snapshot_ref. Сам поиск секретов выше остаётся — он про
        # найденное, а найденное в старом теге тоже надо увидеть.
        snap = _snapshot_ref(repo)
        if snap:
            ctx.note("SKIP %s игнорирует .env: выложен по пину (%s) — правило проверяется по ветке" % (sub, snap))
            continue
        # Нужна именно СТРОКА-правило, а не упоминание: слово «.env» стоит и в комментарии
        # рядом с ним, и проверка «есть ли .env в тексте» проходила после удаления правила —
        # откат это показал.
        gi = repo / ".gitignore"
        lines = [ln.strip() for ln in gi.read_text(encoding="utf-8").splitlines()] if gi.is_file() else []
        ctx.check(
            "%s игнорирует .env" % sub,
            any(ln in (".env", "/.env", ".env*", "*.env") for ln in lines),
            "в .gitignore нет правила на .env: случайная копия файла с токеном уедет в коммит",
        )
    if not seen:
        ctx.note("SKIP no_secrets_test: репозиториев рядом нет")


def pipeline_test(ctx, tree):
    """Репозитории связаны через git и Actions, а не через мою память.

    Поломка 1 октября 2026 показала, где дыра: расписание задач узла уехало в ядро, прошивки
    удалили свои копии, локально всё собралось (там ядро подключено symlink'ом на рабочее
    дерево) — а CI T-Deck упал, потому что берёт ядро строго по `core.ref`, где нужного файла
    ещё нет: `fatal error: sensor_tasks.h: No such file or directory`. Ни одна проверка этого
    не ловила: ядро проверяется в одиночку, прошивка — против своего пина, и состояние
    «прошивка новее пина» не смотрел никто.

    Закрыто с двух концов, и проверка следит за обоими:

    1. `release.py` каждой прошивки ОТКАЗЫВАЕТСЯ отправлять, пока `core.ref` не покрывает
       локальное ядро. Коммит при этом делается: он локальный и никому не мешает.
    2. CI ядра собирает обоих потребителей против ЭТОГО коммита ядра, а не против их пина, —
       то есть выпуск ядра проверяется до того, как поставлен тег.

    Вторая половина смотрит на соседний репозиторий и поэтому пропускается, когда ядро рядом
    выложено по пину: см. `_snapshot_ref`.
    """
    # --- конец первый: прошивка не уедет вперёд пина ---
    seen = 0
    for name, sub in (("форка", "meshcore-fork"), ("tdeck", "tdeck")):
        rel = pathlib.Path(tree) / sub / "scripts" / "release.py"
        if not rel.is_file():
            continue
        seen += 1
        txt = rel.read_text(encoding="utf-8")
        ctx.check(
            "release.py %s умеет сверять core.ref с локальным ядром" % name,
            "def core_pin_covers_local" in txt,
            "нет сверки: прошивка уедет собранной с ядром, которого нет в пине",
        )
        # Отказ должен стоять ДО push, иначе он ничего не отменяет. Ищется ВЫЗОВ, а не
        # определение: строка «def core_pin_covers_local():» тоже содержит имя со скобками,
        # и по ней проверка находила начало файла — то есть проходила всегда, даже когда
        # сверку переносили за push. Откат это и показал.
        guard = txt.find("= core_pin_covers_local()")
        push = txt.find('git_try("push"')
        ctx.check(
            "отказ стоит до отправки у %s" % name,
            guard != -1 and push != -1 and guard < push,
            "сверка есть, но после push — отправка уже случилась",
        )
        ctx.check(
            "при расхождении %s не отправляет" % name,
            "отправка ОТМЕНЕНА" in txt,
            "сверка не приводит к отказу от отправки",
        )

    # --- конец второй: ядро собирает потребителей ---
    core = pathlib.Path(tree) / "mesh-network-core"
    wf = core / ".github" / "workflows" / "checks.yml"
    snap = _snapshot_ref(core) if (core / ".git").exists() else None
    if snap:
        ctx.note("SKIP задание на потребителей: ядро выложено по пину (%s) — задание проверяется по ветке" % snap)
    elif wf.is_file():
        job = _job_block(wf.read_text(encoding="utf-8"), "consumers")
        ctx.check(
            "в CI ядра есть задание на потребителей",
            job is not None,
            "ядро проверяется в одиночку — выпуск сломает прошивку незаметно",
        )
        if job:
            for repo in ("meshcore-fork", "tdeck"):
                ctx.check(
                    "потребитель %s есть в матрице задания" % repo,
                    ("repo: " + repo) in job,
                    "задание проверяет не всех потребителей, а ядро у них одно",
                )
            ctx.check("потребитель собирается в задании", "pio run" in job, "задание есть, но прошивку не собирает")
            ctx.check(
                "сборка потребителя не коммитит",
                "NOGIT" in job,
                "без NOGIT пост-действие сборки закоммитит и отправит из CI — петля",
            )
            # Пин потребителя здесь соблюдать нельзя: смысл задания в сборке с ЭТИМ ядром.
            ctx.check(
                "задание не подменяет ядро пином потребителя",
                "core.ref" not in job,
                "задание читает core.ref — тогда оно проверяет не это ядро, а старое",
            )
            # Приватный tdeck выкачивается deploy key'ем, а не токеном учётной записи. Ядро —
            # репозиторий ПУБЛИЧНЫЙ: личный токен со scope repo в его секретах открыл бы все
            # репозитории владельца, тогда как ключ привязан к одному и только на чтение.
            ctx.check(
                "приватный потребитель выкачивается ключом, а не личным токеном",
                "ssh-key:" in job and "CONSUMERS_TOKEN" not in job,
                "в задании личный токен: в секретах публичного репозитория он даёт "
                "доступ ко всем репозиториям владельца, а нужен один и на чтение",
            )
    if not seen:
        ctx.note("SKIP pipeline_test: прошивок рядом нет")


def wiring_test(ctx, pkg=None):
    """Ни одна написанная проверка не потерялась по дороге к запуску."""
    pkg = pathlib.Path(pkg) if pkg else pathlib.Path(__file__).resolve().parent
    suites = sorted(pkg.glob("suite_*.py"))
    ctx.check("наборы проверок на месте", len(suites) >= 3, "найдено файлов suite_*.py: %d" % len(suites))

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
    ctx.check("каждая написанная проверка кем-то вызывается", not orphans, "никто не зовёт: " + ", ".join(orphans))

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
        ctx.check(
            "обёртка %s зовёт общий запускатель" % sub,
            "mesh-network-tools" in txt and "selftest.py" in txt,
            "%s не ссылается на репозиторий проверок" % shim,
        )
        ctx.check(
            "обёртка %s запускает цель %s" % (sub, target),
            '"--target", "%s"' % target in txt,
            "в %s не найдена цель %s" % (shim, target),
        )


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
        if not harness.firmware_present(tree, sub):
            continue  # прошивки нет рядом — проверять нечего
        with tempfile.TemporaryDirectory(prefix="solo-") as tmp:
            root = pathlib.Path(tmp)
            (root / sub).symlink_to(src, target_is_directory=True)
            # Ядро кладём рядом ССЫЛКОЙ: корень дерева указывает на каталог ядра (как в
            # selftest.py), а копия в 40 МБ ради проверки ни к чему.
            (root / "mesh-network-core").symlink_to(tree / "mesh-network-core", target_is_directory=True)
            solo = harness.Ctx(root / sub, tree / "mesh-network-core", "fork", tree=root)
            # Тишина: прогон внутри проверки не должен выглядеть как ещё одна проверка.
            buf = io.StringIO()
            try:
                with contextlib.redirect_stdout(buf):
                    suite_core.weak_hooks_test(solo)
                    suite_core.ota_screen_progress_test(solo)
                    suite_core.any_session_test(solo)
            except Exception as e:  # noqa: BLE001 — падение здесь и есть ложь проверки
                ctx.check(
                    "проверки ядра живут без второй прошивки (%s)" % sub,
                    False,
                    "%s: %s: %s" % (type(e).__name__, e, (buf.getvalue() or "").strip()[-400:]),
                )
                continue
            ctx.check(
                "проверки ядра живут без второй прошивки (%s)" % sub,
                not solo.failures,
                "упали без второй прошивки на диске: %s — по правилу из targets.py "
                "молчание честнее выдуманного «OK»" % ", ".join(solo.failures[:6]),
            )


def _py_dirs_from_makefile(txt, var="PY_DIRS_ALL"):
    """Каталоги из переменной охвата в корневом Makefile."""
    m = re.search(r"(?m)^%s\s*=\s*((?:[^\n]*\\\n)*[^\n]*)" % re.escape(var), txt)
    if not m:
        return None
    return {p for p in m.group(1).replace("\\", " ").split() if p}


def lint_scope_test(ctx, tree):
    """Линтер Python обязан смотреть на ВЕСЬ наш Python, а не на часть.

    Как это было сломано: переменная PY_DIRS называлась PY_FILES, перечисляла файлы и не
    использовалась ни одной целью — цели (`lint-py`, `format-py`, `format-py-check`)
    перечисляли пути сами, и там стоял только `mesh-network-tools`. Снаружи это выглядело
    благополучно: `make lint-py` печатал «All checks passed», CI обеих прошивок звал именно
    его и был зелёным, — а `ruff check .` из корня показывал 23 замечания, все до единого в
    скриптах сборки прошивок, которых цель не видела. Проверка ровно про это: охват
    описан в одном месте и покрывает каждый каталог, где лежит наш .py.

    Чужой Python не считается: .pio/libdeps выкачивает PlatformIO, MeshCore — апстрим рядом.
    """
    tree = pathlib.Path(tree)
    mk = tree / "Makefile"
    if not mk.is_file():
        ctx.note("SKIP lint_scope_test: корневого Makefile рядом нет")
        return
    txt = mk.read_text(encoding="utf-8")

    declared = _py_dirs_from_makefile(txt)
    ctx.check(
        "охват Python описан переменной PY_DIRS_ALL",
        declared is not None,
        "в Makefile нет PY_DIRS_ALL: охват снова размазан по целям, и расширить его в одном месте нельзя",
    )
    if declared is None:
        return

    # ruff падает с E902 на пути, которого нет, а в CI прошивки рядом лежит РОВНО ОДНА
    # (вторая не выкачивается). Поэтому цели получают не объявленный список, а отфильтрованный
    # по существующим каталогам — иначе сборка tdeck красная из-за meshcore-fork и наоборот.
    ctx.check(
        "охват отфильтрован по существующим каталогам",
        re.search(r"(?m)^PY_DIRS\s*=\s*\$\(wildcard\s+\$\(PY_DIRS_ALL\)\)", txt) is not None,
        "PY_DIRS не фильтруется через $(wildcard): в CI рядом одна прошивка, и ruff упадёт "
        "с E902 на каталоге второй — у обеих прошивок красный CI",
    )

    # Цель, перечисляющая пути сама, обходит PY_DIRS — именно так охват и потерялся.
    for target in ("lint-py", "format-py", "format-py-check"):
        body = re.search(r"(?m)^%s:\n((?:\t[^\n]*\n)+)" % re.escape(target), txt)
        ctx.check(
            "цель %s есть в Makefile" % target,
            body is not None,
            "цель исчезла — конвейер её больше не зовёт",
        )
        if not body:
            continue
        ctx.check(
            "цель %s берёт охват из PY_DIRS" % target,
            "$(PY_DIRS)" in body.group(1),
            "%s перечисляет пути сама: охват разойдётся с PY_DIRS молча" % target,
        )

    # Каждый каталог с нашим .py обязан быть в охвате. Прошивки рядом может и не быть —
    # CI клонирует одну (см. solo_tree_test), поэтому отсутствующие каталоги пропускаются.
    skip = ("MeshCore", ".pio", "__pycache__", ".git", ".ruff_cache")
    missing = []
    for path in sorted(tree.rglob("*.py")):
        rel = path.relative_to(tree)
        if any(part in skip for part in rel.parts):
            continue
        if str(rel.parent) not in declared:
            missing.append(str(rel))
    ctx.check(
        "каждый наш .py лежит в каталоге из PY_DIRS",
        not missing,
        "вне охвата линтера: " + ", ".join(missing[:8]),
    )

    # Обратная сторона: объявлен каталог, которого нет и который ничего не покрывает.
    stale = [d for d in sorted(declared) if (tree / d).exists() and not list((tree / d).glob("*.py"))]
    ctx.check(
        "в PY_DIRS нет каталогов без Python",
        not stale,
        "каталог в охвате, а .py в нём нет: " + ", ".join(stale),
    )


_FAKE_TARGET_CC = """#!/usr/bin/env python3
# Поддельный целевой компилятор: отвечает ровно на те два вопроса, которые задаёт
# tools/clang_tidy.py. Нужен затем, чтобы проверка не требовала установленного xtensa-gcc.
import sys

args = sys.argv[1:]
inc = sys.argv[0] + ".inc"
if "-dM" in args:
    print("#define __XTENSA__ 1")
    print("#define __SIZEOF_POINTER__ 4")
    print("#define __FLT32_MAX__ 3.40282346638528859812e+38F32")
    print("#define __GNUC__ 8")
else:
    sys.stderr.write("#include <...> search starts here:\\n %s\\nEnd of search list.\\n" % inc)
"""

_FAKE_HOST_CLANG = """#!/usr/bin/env python3
# Поддельный хостовый clang: предопределений xtensa у него нет (как у настоящего), а
# -mlongcalls он не знает (как настоящий).
import sys

args = sys.argv[1:]
if "-dM" in args:
    print("#define __GNUC__ 4")
    print("#define __SIZEOF_POINTER__ 8")
elif any(a.startswith("-mlongcalls") for a in args):
    sys.stderr.write("error: unknown argument '-mlongcalls'\\n")
    sys.exit(1)
"""


def lint_target_version_test(ctx, tree):
    """`target-version` линтера не ниже самого старого Python, на котором код запускают.

    Занижение здесь не ошибка сборки, а молчаливый запрет: ruff не предлагает идиом новее
    указанной версии, и часть правил UP просто не срабатывает. В корне стояло `py39` при
    Python 3.11 в CI обеих прошивок и 3.12 в CI ядра — то есть линтер судил код по
    требованиям, которых к нему никто не предъявляет.

    Сравнение идёт с самой СТАРОЙ версией из workflow: на ней код обязан работать, и
    разрешать линтеру идиомы новее неё нельзя — CI прошивки упадёт на синтаксисе. Поэтому
    проверка двусторонняя: занижение прячет правила, завышение ломает сборку.

    MeshCore не считается: это апстрим рядом с деревом, он не наш и в линт не входит.
    """
    tree = pathlib.Path(tree)
    cfg = tree / "pyproject.toml"
    if not cfg.is_file():
        ctx.note("SKIP lint_target_version_test: корневого pyproject.toml рядом нет")
        return
    m = re.search(r'(?m)^\s*target-version\s*=\s*"py(\d)(\d+)"', cfg.read_text(encoding="utf-8"))
    if not ctx.check("pyproject объявляет target-version", m is not None, "в pyproject.toml его нет"):
        return
    declared = (int(m.group(1)), int(m.group(2)))

    found = {}
    for sub in ("mesh-network-core", "mesh-network-tools", "meshcore-fork", "tdeck"):
        wf = tree / sub / ".github" / "workflows"
        if not harness.repo_present(tree, sub) or not wf.is_dir():
            continue
        for f in sorted(wf.glob("*.yml")) + sorted(wf.glob("*.yaml")):
            for ver in re.findall(r"(?m)^\s*python-version:\s*'?\"?(\d+)\.(\d+)", f.read_text(encoding="utf-8")):
                found[(int(ver[0]), int(ver[1]))] = "%s/%s" % (sub, f.name)
    if not found:
        ctx.note("SKIP lint_target_version_test: workflow с python-version рядом нет")
        return
    oldest = min(found)
    ctx.check(
        "target-version совпадает с самым старым Python в CI (%d.%d)" % oldest,
        declared == oldest,
        "в pyproject py%d%d, а в %s стоит Python %d.%d: %s"
        % (
            declared[0],
            declared[1],
            found[oldest],
            oldest[0],
            oldest[1],
            "линтер молча не предлагает новые идиомы"
            if declared < oldest
            else "линтер разрешит идиомы, на которых CI упадёт",
        ),
    )


def tidy_target_env_test(ctx, tree):
    """clang-tidy разбирает код как ЦЕЛЕВОЙ компилятор, а не как хостовый.

    Так это было сломано, и сломано молча. Стандартные заголовки в базе компиляции не
    перечислены — компилятор знает их сам, и у xtensa-gcc это newlib, а у clang хостовые
    /usr/include. Разбор шёл против glibc и давал «function-like macro '__GLIBC_USE' is not
    defined», «unknown type name '__mbstate_t'», а после десятка таких — «too many errors
    emitted, stopping now»: НАСТОЯЩИЕ замечания в этом файле не считались вовсе, и файл при
    этом выглядел проверенным. На полном прогоне 19.10.2026 так терялось 761 замечание.

    Вторая половина той же поломки: без `-m32` указатель на хосте 8 байт, и заголовки
    ESP-IDF ругались на приведение указателя к uint32_t; без `__XTENSA__` заголовки уходили
    в ветку «не xtensa», где лежит `#include "../hal.h"` — файла с таким путём в этой
    раскладке SDK нет, и разбор падал на первом же Arduino.h.

    Проверка не требует ни xtensa-gcc, ни clang: оба подменяются скриптами, которые
    отвечают на те же два вопроса (`-E -v` и `-dM -E`). Смотрим на ОЧИЩЕННУЮ базу — именно
    её читает clang-tidy, и именно в неё должны попасть флаги цели."""
    tree = pathlib.Path(tree)
    script = tree / "tools" / "clang_tidy.py"
    if not script.is_file():
        ctx.note("SKIP tidy_target_env_test: корневого tools/clang_tidy.py рядом нет")
        return

    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        proj = tmp / "proj"
        proj.mkdir()
        cc = tmp / "fake-target-gcc"
        cc.write_text(_FAKE_TARGET_CC, encoding="utf-8")
        cc.chmod(0o755)
        sysinc = pathlib.Path(str(cc) + ".inc")  # каталог «стандартных заголовков» цели
        sysinc.mkdir()
        clang = tmp / "fake-host-clang"
        clang.write_text(_FAKE_HOST_CLANG, encoding="utf-8")
        clang.chmod(0o755)
        (proj / "a.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
        (proj / "compile_commands.json").write_text(
            json.dumps(
                [
                    {
                        "directory": str(proj),
                        "file": "a.cpp",
                        "arguments": [str(cc), "-Iinclude", "-mlongcalls", "-c", "-o", "a.o", "a.cpp"],
                    }
                ]
            ),
            encoding="utf-8",
        )
        out = tmp / "out"
        run = subprocess.run(
            [
                sys.executable,
                str(script),
                "--project",
                str(proj),
                "--out",
                str(out),
                "--clang",
                str(clang),
                "--tidy",
                str(clang),
            ],
            capture_output=True,
            text=True,
        )
        clean = out / "proj" / "compile_commands.json"
        if not ctx.check(
            "clang_tidy.py пишет очищенную базу",
            clean.is_file(),
            "очищенной базы нет: %s%s" % (run.stdout.strip(), run.stderr.strip()),
        ):
            return
        args = json.loads(clean.read_text(encoding="utf-8"))[0]["arguments"]

    ctx.check(
        "очищенная база вырезает хостовые заголовки (-nostdinc)",
        "-nostdinc" in args,
        "флага нет: clang разберёт код против /usr/include и утонет в clang-diagnostic-error",
    )
    ctx.check(
        "очищенная база подставляет заголовки цели (-isystem)",
        "-isystem" in args and str(sysinc) in args,
        "каталогов целевого компилятора нет: %s" % " ".join(args),
    )
    ctx.check(
        "очищенная база учитывает разрядность цели (-m32)",
        "-m32" in args,
        "флага нет: указатель хоста 8 байт, и заголовки ESP-IDF дадут ошибку приведения",
    )
    ctx.check(
        "очищенная база несёт опознавательные макросы цели",
        "-D__XTENSA__" in args or "-D__XTENSA__=1" in args,
        "макроса нет: заголовки уйдут в ветку «не xtensa» и упрутся в '../hal.h'",
    )
    # Числовые пределы цели подменять незачем: модель чисел у clang своя, а сломать ими
    # разбор заголовков легко. В отбор проходят только признаки (пустое значение или 1).
    ctx.check(
        "числовые предопределения цели не подставляются",
        not any(a.startswith("-D__FLT32_MAX__") for a in args),
        "в базу уехал числовой предел: %s" % " ".join(a for a in args if a.startswith("-D__FLT")),
    )
    # Прежнее поведение на месте: чужие для clang флаги по-прежнему вырезаются.
    ctx.check(
        "чужие флаги по-прежнему вырезаются",
        "-mlongcalls" not in args and "-c" not in args,
        "в очищенной базе остался флаг, которого clang не понимает: %s" % " ".join(args),
    )


def lint_suppressions_test(ctx, tree):
    """Послабления линтера адресны и не переживают файл, которому были нужны.

    F821 в скриптах PlatformIO подавлен потому, что `env` и `Import` впрыскивает SCons —
    в файле их определения нет и быть не может. Подавление сделано пофайлово в
    pyproject.toml, а не глобально через `builtins`: глобально оно скрыло бы настоящую
    опечатку в любом файле дерева. Опасность такого списка — он живёт дольше причины:
    файл переименовали или F821 из него ушёл, а послабление осталось и уже прячет ошибку.
    """
    tree = pathlib.Path(tree)
    cfg = tree / "pyproject.toml"
    if not cfg.is_file():
        ctx.note("SKIP lint_suppressions_test: pyproject.toml рядом нет")
        return
    txt = cfg.read_text(encoding="utf-8")

    block = txt.split("[tool.ruff.lint.per-file-ignores]", 1)
    if len(block) == 1:
        ctx.note("SKIP lint_suppressions_test: послаблений нет — проверять нечего")
        return
    listed = re.findall(r'(?m)^"([^"]+)"\s*=\s*\[([^\]]*)\]', block[1])
    ctx.check("послабления разобрались", bool(listed), "секция per-file-ignores есть, а записей в ней нет")

    # Глобального подавления быть не должно: оно и есть то, чего список избегает.
    ctx.check(
        "F821 не подавлен глобально",
        not re.search(r"(?m)^\s*builtins\s*=", txt) and '"*" = ' not in block[1],
        "F821 выключен глобально — настоящая опечатка в любом файле станет невидимой",
    )

    for name, codes in listed:
        path = tree / name
        # Прошивки рядом может не быть: CI клонирует одну. Но проверять через exists()
        # нельзя — пустой каталог прошивки появляется САМ: это gitlink надстройки, и её
        # checkout в CI создаёт заглушки под ВСЕ сабмодули (та же ловушка расписана в
        # harness.firmware_present). Для exists() заглушка не отличается от настоящей
        # прошивки, и проверка падала в CI форка на послаблениях tdeck: каталог есть,
        # файлов в нём нет. Признак — непустота: заглушка пуста, прошивка нет.
        top = tree / name.split("/", 1)[0]
        if not top.is_dir() or next(top.iterdir(), None) is None:
            continue
        ctx.check(
            "послабление указывает на существующий файл (%s)" % name,
            path.is_file(),
            "в per-file-ignores путь, которого нет: послабление мёртвое, а выглядит живым",
        )
        if not path.is_file():
            continue
        # Послабление без причины — повод его снять, иначе список растёт и прячет ошибки.
        if "F821" in codes:
            ctx.check(
                "послаблению F821 есть причина (%s)" % name,
                "Import(" in path.read_text(encoding="utf-8"),
                "F821 подавлен, а SCons-впрыска (Import) в файле нет — послабление лишнее",
            )
