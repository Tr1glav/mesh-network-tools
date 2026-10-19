"""Общая обвязка проверок: где лежат исходники, как вырезать из них функции и как
собрать их на хосте.

Раньше эта обвязка существовала двумя копиями — в `scripts/selftest.py` каждого форка, — и
копии успели разойтись. Здесь она одна, а форки отличаются только тем, какие наборы проверок
запускаются и с какими путями: см. mcselftest/targets.py.
"""

import atexit
import pathlib
import re
import shutil
import subprocess
import tempfile


def _sig_re(signature):
    r"""Регексп по фрагменту исходника, устойчивый к расстановке пробелов.

    clang-format пишет «char *x», а сигнатуры в проверках исторически писались «char* x»:
    разница только в пробелах вокруг «*», и проверка не должна от неё зависеть. «*»
    окружается необязательными пробелами, а пробег пробельных символов (в том числе
    переводы строк) считается взаимозаменяемым: clang-format переносит длинные списки
    иначе, чем редактор человека.

    Между двумя словесными символами пробел всё же обязателен. Если ставить там «\s*»,
    шаблон «int\s*meshTxQueuedCount» совпадёт и с «printmeshTxQueuedCountX» — проверка
    «нашла» бы сигнатуру там, где её нет. Рядом с пунктуацией пробел необязателен.
    """
    # Внешние пробелы фрагмента в шаблон не попадают. Иначе ведущий «\s*» съедал бы
    # перевод строки ПЕРЕД фрагментом, и подстановка (src_replace) приклеивалась к
    # предыдущей строке — а если та была комментарием «//», первая строка замены молча
    # уходила в комментарий. Литеральный поиск в src_search идёт по полному фрагменту,
    # так что точные совпадения от этого не меняются.
    pat = re.sub(r"([.^$*+?()\[\]{}|\\])", r"\\\1", signature.strip())
    pat = pat.replace(r"\*", r"\s*\*\s*")

    def _space(m):
        left = pat[m.start() - 1 : m.start()]
        right = pat[m.end() : m.end() + 1]
        word = str.isalnum
        if left and right and (word(left) or left == "_") and (word(right) or right == "_"):
            return r"\s+"
        return r"\s*"

    return re.sub(r"\s+", _space, pat)


def snapshot_ref(repo):
    """Если репозиторий рядом — не рабочая копия, а снимок прошлого, вернуть его описание.

    В CI прошивки соседние репозитории выкладываются по пину: ядро — по `core.ref`, то есть
    на отсоединённой голове у тега. Проверять по такому снимку, КАК репозиторий
    поддерживается сегодня, нельзя, и это не теория: 1 октября 2026 CI форка покраснел на
    проверке «mesh-network-core игнорирует .env». Правило в ядре к тому моменту стояло, но в
    теге v0.9.0, по которому ядро и выкладывается, его ещё не было — а исправить тег форк
    не может никак. Красный CI означал не поломку, а возраст пина.

    Граница проходит по тому, что утверждает проверка: НАЙДЕННОЕ в снимке (секрет в
    отслеживаемом файле) остаётся находкой, где бы его ни увидели; ОТСУТСТВИЕ правила
    поддержки (строка в .gitignore, задание в workflow, номер версии в library.json) про
    снимок ничего не говорит, и такие проверки пропускаются с записью в журнал. На ветке —
    в рабочем дереве и в своём CI репозитория — проверяется всё.
    """
    r = subprocess.run(["git", "symbolic-ref", "-q", "HEAD"], cwd=str(repo), capture_output=True, text=True)
    if r.returncode == 0:
        return None  # голова на ветке — это живая копия, а не снимок
    d = subprocess.run(["git", "describe", "--tags", "--always"], cwd=str(repo), capture_output=True, text=True)
    return (d.stdout or "").strip() or "отсоединённая голова"


def repo_present(tree, sub):
    """Выложен ли рядом репозиторий `sub` — по-настоящему, а не пустым каталогом.

    Парная к firmware_present, но вопрос другой: проверки вроде ci_present_test смотрят и
    на ядро с набором проверок, а platformio.ini есть только у прошивок. Признак — свой
    .git: пустой каталог-заглушка (gitlink надстройки в CI, clone без --recursive) его не
    имеет, и проверка честно пропускается вместо провала «у tdeck нет workflow».
    """
    return (tree / sub / ".git").exists()


def firmware_present(tree, sub):
    """Лежит ли рядом прошивка `sub` — по-настоящему, а не одним пустым каталогом.

    Проверять через is_dir() нельзя. Пустой каталог прошивки появляется сам: это
    gitlink в надстройке (её checkout в CI создаёт заглушки под все сабмодули), и он же
    остаётся после `git clone` без --recursive. Для is_dir() такой каталог ничем не
    отличается от настоящей прошивки, и проверка вместо честного SKIP падала с
    FileNotFoundError на первом же чтении. Признак наличия — platformio.ini: без него
    это не прошивка, а место, где она должна быть.
    """
    return (tree / sub / "platformio.ini").is_file()


def src_search(text, fragment, pos=0):
    r"""Границы фрагмента исходника: (начало, конец) либо None.

    Сначала литеральный поиск, и только при промахе — нечувствительный к пробелам.
    Порядок важен: литерал сохраняет прежнее поведение везде, где текст не менялся,
    и позиционные маркеры вроде "\n}\n" продолжают значить ровно то, что значили
    (фаззи-шаблон для них — это «\s*\}\s*», то есть первая же закрывающая скобка:
    срез обрывался на ней, и проверки искали код в куске, который до него не доходил).
    Фаззи-поиск остаётся запасным путём для фрагментов, которые разъехались по строкам
    после прогона clang-format.
    """
    i = text.find(fragment, pos)
    if i >= 0:
        return i, i + len(fragment)
    m = re.search(_sig_re(fragment), text[pos:])
    if m is None:
        return None
    return pos + m.start(), pos + m.end()


def src_index(text, fragment, pos=0):
    """Позиция фрагмента исходника. Бросает ValueError, если его нет вовсе."""
    found = src_search(text, fragment, pos)
    if found is None:
        raise ValueError("фрагмент исходника не найден: %s" % fragment)
    return found[0]


def src_replace(text, fragment, replacement):
    """Заменяет фрагмент исходника, не глядя на расстановку пробелов.

    Нужна проверкам, которые подменяют кусок настоящего кода своей заглушкой перед
    сборкой на хосте: литеральный replace() после переноса строк форматтером молча
    не срабатывал, и проверка превращалась в фиктивную.
    """
    found = src_search(text, fragment)
    if found is None:
        return text
    a, b = found
    return text[:a] + replacement + text[b:]


_C_EXT = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
# «char *x» → «char* x»: приводим указатели к виду, к которому писались проверки.
_PTR_RIGHT = re.compile(r"([A-Za-z0-9_>])\s+\*([A-Za-z_])")
# «__attribute__((weak)) void f()» → атрибут отдельной строкой. clang-format приклеивает
# атрибут к объявлению, а разбор заглушек (`_hook_defs`) ждёт тип в начале строки.
_ATTR = re.compile(r"(__attribute__\s*\(\([^\n]*?\)\))\s+(?=[A-Za-z_])")


def normalize_source(text):
    """Приводит исходник к «человеческому» виду, к которому писались проверки.

    Проверки сравнивают вырезанные из исходников фрагменты как обычный текст, поэтому
    расстановка пробелов форматтером не должна их ломать. clang-format пишет указатели
    как «char *x», а исторически в дереве было «char* x» — возвращаем прежний вид.
    Атрибуты (`__attribute__((weak))`) clang-format приклеивает к объявлению; возвращаем
    их на отдельную строку — так их видят разборщики заглушек. Переводы строк не
    схлопываем: на них держатся якоря (?m)^ в шаблонах.
    """
    text = _PTR_RIGHT.sub(r"\1* \2", text)
    return _ATTR.sub(r"\1\n", text)


_orig_read_text = pathlib.Path.read_text


def _read_text(self, *args, **kwargs):
    text = _orig_read_text(self, *args, **kwargs)
    if self.suffix.lower() in _C_EXT:
        return normalize_source(text)
    return text


def install_source_normalization():
    """Делает чтение исходников C/C++ нечувствительным к стилю форматтера.

    Подмена глобальная и потому нарочно узкая: трогаем только файлы с расширением C/C++
    и только на время прогона — selftest.py снимает её через try/finally
    (`uninstall_source_normalization`). Проверки читают файлы как
    `(ctx.core / "src/x.cpp").read_text()`, поэтому подменять приходится сам метод
    чтения, а не каждый вызов; чище было бы править сигнатуры в самих проверках, но их
    там сотни.

    Повторный вызов безвреден: исходный метод запомнен один раз, на импорте модуля.
    """
    pathlib.Path.read_text = _read_text


def uninstall_source_normalization():
    """Возвращает pathlib.Path.read_text на место. Парная к install_*."""
    pathlib.Path.read_text = _orig_read_text


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
        print(("OK   " if ok else "FAIL ") + name + ((" — " + detail) if detail and not ok else ""))
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
        if not (path.is_file() and src_search(path.read_text(encoding="utf-8"), signature)):
            dirs = (self.root / "lib/meshcore/src", self.root / "src", self.core / "src")
            for cand in sorted(p for d in dirs if d.is_dir() for p in d.glob("*.cpp")):
                if src_search(cand.read_text(encoding="utf-8"), signature):
                    path = cand
                    break
            else:
                raise RuntimeError("не найдена функция %s (прошивка: %s, ядро: %s)" % (signature, self.root, self.core))
        src = path.read_text(encoding="utf-8")
        start = src_index(src, signature)
        depth = 0
        for i in range(src.index("{", start), len(src)):
            if src[i] == "{":
                depth += 1
            elif src[i] == "}":
                depth -= 1
                if depth == 0:
                    return src[start : i + 1]
        raise RuntimeError("не найден конец функции " + signature)

    def span(self, hint, start_marker, end_marker):
        """Вырезает кусок исходника между двумя маркерами включительно.

        Нужно там, где не функция, а объявления: состояние очереди ретранслятора объявлено
        отдельно от функций, которые им пользуются, и без него вырезанные функции не
        соберутся. В отличие от grab() не считает скобки — маркеры должны быть точными.
        """
        path = hint if isinstance(hint, pathlib.Path) else self.root / hint
        src = path.read_text(encoding="utf-8")
        a = src_index(src, start_marker)
        end = src_search(src, end_marker, a)
        if end is None:
            raise RuntimeError("не найден конечный маркер %r (файл: %s)" % (end_marker, path))
        return src[a : end[1]]

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
            ["g++", "-std=c++17", "-fsanitize=address,undefined", "-g", str(src), "-o", str(exe)],
            capture_output=True,
            text=True,
        )
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
