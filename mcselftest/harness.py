"""Общая обвязка проверок: где лежат исходники, как вырезать из них функции и как
собрать их на хосте.

Раньше эта обвязка существовала двумя копиями — в `scripts/selftest.py` каждого форка, — и
копии успели разойтись. Здесь она одна, а форки отличаются только тем, какие наборы проверок
запускаются и с какими путями: см. mcselftest/targets.py.
"""
import atexit
import pathlib
import shutil
import subprocess
import tempfile


class Ctx:
    """Всё, что нужно проверке: пути, счётчик провалов и инструменты.

    root — каталог проверяемой прошивки (`meshcore-fork` или `tdeck`); для цели `core` он
    совпадает с каталогом ядра, потому что проверять больше нечего.
    core — каталог ядра протокола `mesh-network-core`.
    Оба пути передаются снаружи, а не вычисляются здесь: одна и та же проверка запускается
    для разных прошивок, и зашитый путь сделал бы её непереносимой — ровно то, из-за чего
    обвязка и разошлась на две копии.
    """

    def __init__(self, root, core, target, tree=None):
        self.root = pathlib.Path(root)
        self.core = pathlib.Path(core)
        # Рабочее дерево: каталог, в котором лежат ВСЕ репозитории. Нужен кросс-репозиторным
        # проверкам — тем, что смотрят сразу в обе прошивки (например «ни один features.h не
        # переопределяет FEATURE_RELAY»). Через ctx.root их не выразить: у цели `core` он
        # указывает на ядро, где никаких прошивок нет.
        self.tree = pathlib.Path(tree) if tree else self.core.parent
        self.target = target
        self.failures = []
        self._tmpdirs = []
        # Каталоги собранных тестов живут до конца прогона: бинарник нужен после сборки, и
        # сносить его раньше нельзя. Чистим на выходе, включая аварийный.
        atexit.register(self._cleanup)

    def _cleanup(self):
        for d in self._tmpdirs:
            shutil.rmtree(d, ignore_errors=True)

    # ===== Результат =====

    def check(self, name, ok, detail=""):
        print(("OK   " if ok else "FAIL ") + name +
              ((" — " + detail) if detail and not ok else ""))
        if not ok:
            self.failures.append(name)
        return ok

    def note(self, text):
        """Строка в вывод, которая не является проверкой: сводка, пояснение, SKIP."""
        print(text)

    # ===== Исходники =====

    def grab(self, hint, signature):
        """Вырезает функцию из исходника по началу сигнатуры, считая фигурные скобки.

        hint — строка (путь от корня прошивки) либо готовый Path: функции ядра берутся как
        ctx.core / "src/crypto.cpp", функции прошивки — как "lib/meshcore/src/mqtt.cpp".
        """
        # Путь — подсказка, а не требование: файлы переезжают при разборке на модули, а то и
        # целиком уезжают в отдельный репозиторий, и жёсткая привязка ломает проверки на
        # ровном месте. Не нашлось по подсказке (в том числе если файла вовсе нет) — ищем
        # сигнатуру по всем исходникам прошивки и ядра.
        path = hint if isinstance(hint, pathlib.Path) else self.root / hint
        if not (path.is_file() and signature in path.read_text(encoding="utf-8")):
            dirs = (self.root / "lib/meshcore/src", self.root / "src", self.core / "src")
            for cand in sorted(p for d in dirs if d.is_dir() for p in d.glob("*.cpp")):
                if signature in cand.read_text(encoding="utf-8"):
                    path = cand
                    break
            else:
                raise RuntimeError("не найдена функция %s (прошивка: %s, ядро: %s)"
                                   % (signature, self.root, self.core))
        src = path.read_text(encoding="utf-8")
        start = src.index(signature)
        depth = 0
        for i in range(src.index("{", start), len(src)):
            if src[i] == "{":
                depth += 1
            elif src[i] == "}":
                depth -= 1
                if depth == 0:
                    return src[start:i + 1]
        raise RuntimeError("не найден конец функции " + signature)

    def span(self, hint, start_marker, end_marker):
        """Вырезает кусок исходника между двумя маркерами включительно.

        Нужно там, где не функция, а объявления: состояние очереди ретранслятора объявлено
        отдельно от функций, которые им пользуются, и без него вырезанные функции не
        соберутся. В отличие от grab() не считает скобки — маркеры должны быть точными.
        """
        path = hint if isinstance(hint, pathlib.Path) else self.root / hint
        src = path.read_text(encoding="utf-8")
        a = src.index(start_marker)
        b = src.index(end_marker, a)
        return src[a:b + len(end_marker)]

    # ===== Сборка на хосте =====

    def host_build(self, code, name):
        """Собирает код на хосте с санитайзерами. Возвращает (путь к бинарнику, текст ошибки).

        Каталог держим до конца прогона (чистим на выходе), а не на время вызова: иначе
        бинарник исчезнет раньше, чем его запустят.
        """
        tmp = tempfile.mkdtemp(prefix="meshselftest-")
        self._tmpdirs.append(tmp)
        src = pathlib.Path(tmp) / name
        exe = pathlib.Path(tmp) / "a.out"
        src.write_text(code, encoding="utf-8")
        build = subprocess.run(
            ["g++", "-std=c++17", "-fsanitize=address,undefined", "-g",
             str(src), "-o", str(exe)],
            capture_output=True, text=True)
        if build.returncode != 0:
            return None, build.stderr
        return exe, ""

    def host_run(self, code, name, label, limit=400):
        """Собрать и запустить: возвращает (ok, stdout). Ошибка сборки — это провал
        проверки, а не исключение: собранный не тем компилятором тест обязан быть виден в
        выводе, а не уронить весь прогон."""
        if not shutil.which("g++"):
            self.note("SKIP g++ не найден — «%s» не проверено" % label)
            return None, ""
        exe, err = self.host_build(code, name)
        if exe is None:
            self.check("сборка теста «%s»" % label, False, err.strip()[:limit])
            return False, ""
        run = subprocess.run([str(exe)], capture_output=True, text=True)
        return run.returncode == 0, (run.stdout + run.stderr)


def have_gpp():
    return shutil.which("g++") is not None
