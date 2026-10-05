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
import subprocess
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


def _snapshot_ref(repo):
    """Если репозиторий рядом — не рабочая копия, а снимок прошлого, вернуть его описание.

    В CI прошивки соседние репозитории выкладываются по пину: ядро — по `core.ref`, то есть
    на отсоединённой голове у тега. Проверять по такому снимку, КАК репозиторий
    поддерживается сегодня, нельзя, и это не теория: 1 октября 2026 CI форка покраснел на
    проверке «mesh-network-core игнорирует .env». Правило в ядре к тому моменту стояло, но в
    теге v0.9.0, по которому ядро и выкладывается, его ещё не было — а исправить тег форк
    не может никак. Красный CI означал не поломку, а возраст пина.

    Граница проходит по тому, что утверждает проверка: НАЙДЕННОЕ в снимке (секрет в
    отслеживаемом файле) остаётся находкой, где бы его ни увидели; ОТСУТСТВИЕ правила
    поддержки (строка в .gitignore, задание в workflow) про снимок ничего не говорит, и
    такие проверки пропускаются с записью в журнал. На ветке — в рабочем дереве и в своём
    CI репозитория — проверяется всё.
    """
    r = subprocess.run(["git", "symbolic-ref", "-q", "HEAD"], cwd=str(repo),
                       capture_output=True, text=True)
    if r.returncode == 0:
        return None                 # голова на ветке — это живая копия, а не снимок
    d = subprocess.run(["git", "describe", "--tags", "--always"], cwd=str(repo),
                       capture_output=True, text=True)
    return (d.stdout or "").strip() or "отсоединённая голова"


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
        snap = _snapshot_ref(repo)
        if snap:
            ctx.note("SKIP %s: выложен по пину (%s), а не рабочей копией — свой CI "
                     "проверяется по ветке" % (sub, snap))
            continue
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


def no_secrets_test(ctx, tree):
    """Ни один репозиторий не держит у себя токен или приватный ключ.

    Токен GitHub лежит в `.env` в корне рабочего дерева, а корень под git НЕ находится — туда
    он и положен затем, чтобы физически не попасть ни в один коммит. Внутри репозитория такой
    файл попал бы, и цена ошибки — секрет в истории публичного репозитория, откуда его уже не
    убрать переписыванием.

    Проверка ищет не конкретное значение (хранить его здесь означало бы ровно то, от чего
    защищаемся), а признаки формата: префиксы токенов GitHub и шапку приватного ключа. Смотрит
    только отслеживаемые git'ом файлы: `.env` рядом с репозиторием, но вне его, — это норма."""
    # Маркеры собираются из частей намеренно: написанные целиком, они сделали бы ЭТОТ файл
    # «похожим на секрет», и проверка падала бы на себе самой — так и случилось при первом
    # прогоне. Склейка решает это без списка исключений, который пришлось бы поддерживать.
    marks = tuple("github_" + "pat_" for _ in (0,)) + ("gh" + "p_", "gh" + "o_", "gh" + "s_",
                  "BEGIN OPENSSH PRIVATE " + "KEY", "BEGIN RSA PRIVATE " + "KEY")
    seen = 0
    for sub in ("mesh-network-core", "mesh-network-tools", "meshcore-fork", "tdeck"):
        repo = pathlib.Path(tree) / sub
        if not (repo / ".git").exists():
            continue
        seen += 1
        r = subprocess.run(["git", "ls-files", "-z"], cwd=str(repo),
                           capture_output=True, text=True)
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
        ctx.check("%s не держит секретов в отслеживаемых файлах" % sub, not bad,
                  "похоже на секрет: " + "; ".join(bad))
        # Правило в .gitignore — про то, как репозиторий поддерживается СЕЙЧАС, а снимок по
        # пину этого не знает: см. _snapshot_ref. Сам поиск секретов выше остаётся — он про
        # найденное, а найденное в старом теге тоже надо увидеть.
        snap = _snapshot_ref(repo)
        if snap:
            ctx.note("SKIP %s игнорирует .env: выложен по пину (%s) — правило проверяется "
                     "по ветке" % (sub, snap))
            continue
        # Нужна именно СТРОКА-правило, а не упоминание: слово «.env» стоит и в комментарии
        # рядом с ним, и проверка «есть ли .env в тексте» проходила после удаления правила —
        # откат это показал.
        gi = (repo / ".gitignore")
        lines = [ln.strip() for ln in gi.read_text(encoding="utf-8").splitlines()] \
            if gi.is_file() else []
        ctx.check("%s игнорирует .env" % sub,
                  any(ln in (".env", "/.env", ".env*", "*.env") for ln in lines),
                  "в .gitignore нет правила на .env: случайная копия файла с токеном уедет "
                  "в коммит")
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
        ctx.check("release.py %s умеет сверять core.ref с локальным ядром" % name,
                  "def core_pin_covers_local" in txt,
                  "нет сверки: прошивка уедет собранной с ядром, которого нет в пине")
        # Отказ должен стоять ДО push, иначе он ничего не отменяет. Ищется ВЫЗОВ, а не
        # определение: строка «def core_pin_covers_local():» тоже содержит имя со скобками,
        # и по ней проверка находила начало файла — то есть проходила всегда, даже когда
        # сверку переносили за push. Откат это и показал.
        guard = txt.find("= core_pin_covers_local()")
        push = txt.find('git_try("push"')
        ctx.check("отказ стоит до отправки у %s" % name,
                  guard != -1 and push != -1 and guard < push,
                  "сверка есть, но после push — отправка уже случилась")
        ctx.check("при расхождении %s не отправляет" % name,
                  "отправка ОТМЕНЕНА" in txt,
                  "сверка не приводит к отказу от отправки")

    # --- конец второй: ядро собирает потребителей ---
    core = pathlib.Path(tree) / "mesh-network-core"
    wf = core / ".github" / "workflows" / "checks.yml"
    snap = _snapshot_ref(core) if (core / ".git").exists() else None
    if snap:
        ctx.note("SKIP задание на потребителей: ядро выложено по пину (%s) — задание "
                 "проверяется по ветке" % snap)
    elif wf.is_file():
        job = _job_block(wf.read_text(encoding="utf-8"), "consumers")
        ctx.check("в CI ядра есть задание на потребителей", job is not None,
                  "ядро проверяется в одиночку — выпуск сломает прошивку незаметно")
        if job:
            for repo in ("meshcore-fork", "tdeck"):
                ctx.check("потребитель %s есть в матрице задания" % repo,
                          ("repo: " + repo) in job,
                          "задание проверяет не всех потребителей, а ядро у них одно")
            ctx.check("потребитель собирается в задании", "pio run" in job,
                      "задание есть, но прошивку не собирает")
            ctx.check("сборка потребителя не коммитит", "NOGIT" in job,
                      "без NOGIT пост-действие сборки закоммитит и отправит из CI — петля")
            # Пин потребителя здесь соблюдать нельзя: смысл задания в сборке с ЭТИМ ядром.
            ctx.check("задание не подменяет ядро пином потребителя", "core.ref" not in job,
                      "задание читает core.ref — тогда оно проверяет не это ядро, а старое")
            # Приватный tdeck выкачивается deploy key'ем, а не токеном учётной записи. Ядро —
            # репозиторий ПУБЛИЧНЫЙ: личный токен со scope repo в его секретах открыл бы все
            # репозитории владельца, тогда как ключ привязан к одному и только на чтение.
            ctx.check("приватный потребитель выкачивается ключом, а не личным токеном",
                      "ssh-key:" in job and "CONSUMERS_TOKEN" not in job,
                      "в задании личный токен: в секретах публичного репозитория он даёт "
                      "доступ ко всем репозиториям владельца, а нужен один и на чтение")
    if not seen:
        ctx.note("SKIP pipeline_test: прошивок рядом нет")


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
