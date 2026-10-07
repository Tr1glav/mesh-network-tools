"""Проверки прошивки tdeck (LilyGO T-Deck).

Своё: пакет приложения .tapp, шапка ELF, которую разбирает загрузчик приложений, и
кириллица в пропорциональных шрифтах (вынесена в suite_font — она большая и относится к
шрифтам вообще, а не к загрузчику).
Проверки ядра — в suite_core.
"""
import io
import os
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib


# ===== Пакет приложения (.tapp) =====
# Проверяем ровно то, что читает устройство: заголовок, длину, CRC32 и то, что внутри одна
# папка верхнего уровня. Распаковщик на плате отказывает при любом расхождении, и узнать
# об этом лучше здесь, чем на карте.
def tapp_test(ctx):
    import tarfile as tf
    app = ctx.root / "apps" / "calendar"
    if not (app / "setting.json").exists():
        print("SKIP apps/calendar нет — проверка пакета пропущена")
        return
    with tempfile.TemporaryDirectory() as tmp:
        r = subprocess.run([sys.executable, str(ctx.root / "scripts" / "mkapp.py"), str(app),
                            "-o", tmp], capture_output=True, text=True)
        out = pathlib.Path(tmp) / "calendar.tapp"
        ctx.check("mkapp собирает пакет", r.returncode == 0 and out.exists(),
              (r.stdout + r.stderr).strip()[:300])
        if not out.exists():
            return
        blob = out.read_bytes()
        ctx.check("пакет: заголовок TAPP", blob[:4] == b"TAPP")
        size, crc = struct.unpack("<II", blob[4:12])
        try:
            raw = zlib.decompress(blob[12:])
        except zlib.error as e:
            ctx.check("пакет: поток распаковывается", False, str(e))
            return
        ctx.check("пакет: объявленная длина", len(raw) == size,
              "в заголовке %d, распаковалось %d" % (size, len(raw)))
        ctx.check("пакет: CRC32 содержимого", (zlib.crc32(raw) & 0xFFFFFFFF) == crc)
        names = tf.open(fileobj=io.BytesIO(raw)).getnames()
        tops = {n.split("/")[0] for n in names}
        ctx.check("пакет: одна папка верхнего уровня", len(tops) == 1,
              "нашлось: " + ", ".join(sorted(tops)))
        ctx.check("пакет: внутри есть описание",
              any(n.endswith("/setting.json") for n in names), ", ".join(names))
        ctx.check("пакет: без путей наружу",
              all(not n.startswith("/") and ".." not in n for n in names))


# ===== Загрузчик приложений: проверка шапки ELF =====
# Файл приложения приходит с карты памяти или через /upload по сети, то есть это внешний вход
# — и единственный в прошивке, который разбирается своим кодом байт за байтом. На плате такое
# не проверишь: нужен именно битый файл, а не приложение. Поэтому проверка шапки вынесена в
# чистую функцию (elfCheckHeaders), и здесь она собирается хостовым компилятором с
# санитайзерами и получает подделки: обрезанный файл, чужую платформу, сегмент, который
# копируется дальше выделенной памяти, таблицу за концом файла.
ELF_MAIN = """
#include <cstdio>
#include <cstdlib>

int main(int argc, char** argv) {
    if (argc < 2) return 2;
    FILE* f = fopen(argv[1], "rb");
    if (!f) return 2;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    // Ровно по размеру файла, а не с запасом: с запасом санитайзер не увидел бы чтения за
    // концом — а ловим мы именно их.
    uint8_t* buf = (uint8_t*)malloc(n ? n : 1);
    if (fread(buf, 1, n, f) != (size_t)n) return 2;
    fclose(f);
    uint32_t lo = 0, hi = 0;
    const char* why = elfCheckHeaders(buf, (size_t)n, &lo, &hi);
    if (why) printf("ERR %s\\n", why);
    else     printf("OK %u %u\\n", (unsigned)lo, (unsigned)hi);
    free(buf);
    return 0;
}
"""


def elf_sections_test(ctx):
    """Разбор секций ELF: имя секции не читается за границей, REL не разбирается как RELA.

    Файл приложения приходит с карты памяти, то есть целиком извне. Две дыры в разборе:

    1. Имя секции брали как `shNames + s.sh_name`, проверив только, что смещение внутри
       .shstrtab. Нуля в конце строки это не гарантирует: если таблица обрывается без нуля,
       `strcmp` уходит за её границу. Для имён СИМВОЛОВ такая проверка была с самого начала
       (`strAt`), для имён секций — нет.
    2. `.rel.dyn` попадал в тот же разбор, что `.rela.dyn`, и читался структурой `ElfRela` в
       12 байт, тогда как запись REL — 8 байт. Каждая запись брала полтора размера своей, и
       файл разбирался в мусор.

    Проверяется устройство: разбор живёт в большой функции загрузки, которую на хосте не
    собрать (она тянет флеш, PSRAM и таблицу символов прошивки). Но оба утверждения видны в
    исходнике однозначно."""
    src = (ctx.root / "src" / "tdeck_elf.cpp").read_text(encoding="utf-8")
    code = "\n".join((ln if ln.find("//") < 0 else ln[:ln.find("//")])
                     for ln in src.splitlines())

    ctx.check("имя секции берётся через strAt",
              re.search(r"strAt\s*\(\s*shNames\s*,", code) is not None,
              "имя секции читается как shNames + sh_name: без нуля внутри .shstrtab strcmp "
              "уйдёт за границу секции")
    ctx.check("сломанное имя секции — отказ",
              re.search(r"if\s*\(\s*!\s*nm\s*\)\s*return\s+setError", code) is not None,
              "результат strAt для имени секции не проверяется на 0")
    ctx.check("strAt проверяет нуль внутри секции",
              "memchr" in ctx.grab("src/tdeck_elf.cpp", "static const char* strAt("),
              "strAt больше не ищет завершающий нуль — проверка выше стала бессмысленной")

    ctx.check(".rel.dyn отвергается явно",
              re.search(r'strcmp\s*\(\s*nm\s*,\s*"\.rel\.dyn"\s*\)[^;]*?\n?[^;]*?'
                        r'sh_size\s*\)\s*return\s+setError', code) is not None,
              ".rel.dyn не отвергается: он разберётся структурой RELA в 12 байт вместо 8")
    ctx.check("таблица релокаций одна (.rela.dyn)",
              re.search(r"int16_t\s+rela\s*=\s*-1", code) is not None,
              "rela снова массив из двух: значит .rel.dyn опять идёт в разбор RELA")
    ctx.check("размер таблицы релокаций делится на размер записи",
              re.search(r"sh_size\s*%\s*sizeof\s*\(\s*ElfRela\s*\)", code) is not None,
              "хвост таблицы читается за границей секции, а записей считается на одну больше")


def elf_headers_test(ctx):
    if not shutil.which("g++"):
        print("SKIP g++ не найден — шапка ELF не проверена")
        return
    src_text = (ctx.root / "src/tdeck_elf.cpp").read_text(encoding="utf-8")
    m = re.search(r"#define\s+TDECK_ELF_IMAGE_MAX\s+\(([^)]*)\)", src_text)
    if not m:
        ctx.check("границы образа объявлены", False, "не найден TDECK_ELF_IMAGE_MAX")
        return
    image_max = eval(m.group(1).replace("U", ""))

    code = (
        "#include <cstdint>\n#include <cstring>\n#include <cstddef>\n"
        "#define PT_LOAD 1\n#define EM_XTENSA 94\n"
        "#define TDECK_ELF_IMAGE_MAX (%s)\n" % m.group(1)
        + ctx.grab("src/tdeck_elf.cpp", "struct ElfEhdr {") + ";\n"
        + ctx.grab("src/tdeck_elf.cpp", "struct ElfPhdr {") + ";\n"
        + ctx.grab("src/tdeck_elf.cpp", "struct ElfShdr {") + ";\n"
        + ctx.grab("src/tdeck_elf.cpp", "static const char* elfCheckHeaders(") + "\n"
        + ELF_MAIN
    )

    import struct as _s

    def ehdr(**kw):
        f = dict(magic=b"\x7fELF", cls=1, data=1, e_type=2, e_machine=94,
                 phoff=52, phentsize=32, phnum=1, shoff=84, shentsize=40, shnum=1, shstrndx=0)
        f.update(kw)
        ident = f["magic"] + bytes([f["cls"], f["data"], 1, 0]) + b"\0" * 8
        return _s.pack("<16sHHIIIIIHHHHHH", ident, f["e_type"], f["e_machine"], 1, 0,
                       f["phoff"], f["shoff"], 0, 52, f["phentsize"], f["phnum"],
                       f["shentsize"], f["shnum"], f["shstrndx"])

    def phdr(p_type=1, off=0, vaddr=0x3C800000, filesz=0x20, memsz=0x40):
        return _s.pack("<8I", p_type, off, vaddr, vaddr, filesz, memsz, 0, 4)

    def shdr(off=0, size=0):
        return _s.pack("<10I", 0, 3, 0, 0, off, size, 0, 0, 1, 0)

    def elf(eh=None, ph=None, sh=None):
        return (eh if eh is not None else ehdr()) + \
               (ph if ph is not None else phdr()) + \
               (sh if sh is not None else shdr())

    cases = [
        ("годный файл",                 elf(),                                        "OK"),
        ("обрезанный файл",             elf()[:20],                                   "ERR too small"),
        ("не ELF",                      elf(eh=ehdr(magic=b"NOPE")),                  "ERR not ELF"),
        ("64 бита",                     elf(eh=ehdr(cls=2)),                          "ERR not ELF32-LE"),
        ("чужая платформа",             elf(eh=ehdr(e_machine=40)),                   "ERR not Xtensa"),
        ("слишком много заголовков",    elf(eh=ehdr(phnum=17)),                       "ERR too many hdrs"),
        ("таблица программ за концом",  elf(eh=ehdr(phoff=9000)),                     "ERR ph out"),
        ("сегмент за концом файла",     elf(ph=phdr(off=9000)),                       "ERR load out"),
        # Размеры подобраны так, чтобы сработала именно эта проверка: filesz должен влезать
        # в файл, иначе раньше сработает «load out».
        ("filesz больше memsz",         elf(ph=phdr(filesz=0x40, memsz=0x20)),        "ERR filesz > memsz"),
        ("образ короче слова",          elf(ph=phdr(filesz=2, memsz=2)),              "ERR image too small"),
        ("образ больше предела",        elf(ph=phdr(filesz=0, memsz=image_max + 16)), "ERR image too big"),
        ("нет ни одного PT_LOAD",       elf(ph=phdr(p_type=0)),                       "ERR empty image"),
    ]

    with tempfile.TemporaryDirectory() as tmp:
        src = pathlib.Path(tmp) / "elf.cpp"
        exe = pathlib.Path(tmp) / "elf"
        src.write_text(code, encoding="utf-8")
        build = subprocess.run(
            ["g++", "-std=c++17", "-fsanitize=address,undefined", "-g", str(src), "-o", str(exe)],
            capture_output=True, text=True)
        if build.returncode != 0:
            ctx.check("сборка теста шапки ELF", False, build.stderr.strip()[:400])
            return
        bad = []
        for name, data, want in cases:
            f = pathlib.Path(tmp) / "case.elf"
            f.write_bytes(data)
            run = subprocess.run([str(exe), str(f)], capture_output=True, text=True)
            got = run.stdout.strip()
            ok = (got.startswith("OK") if want == "OK" else got == want)
            if run.returncode != 0 or not ok:
                bad.append("%s: ожидалось «%s», получено «%s»%s"
                           % (name, want, got, " (санитайзер)" if run.returncode else ""))
        ctx.check("шапка ELF: %d подделок отвергнуты, годный файл принят" % (len(cases) - 1),
              not bad, "; ".join(bad)[:400])


# ===== Добавка к общей проверке границ буферов =====
# fmtUdeg лежит в ядре, nmeaCoord — в прошивке T-Deck, но проверяются они вместе и в той же
# сборке, что буферные функции ядра: это две стороны одного пути координат, и ошибка здесь не
# падает, а тихо сдвигает точку на карте. Передаются в suite_core.host_functions_test.
HOST_EXTRA_FUNCS = (
    # fmtUdeg лежит в ядре: подсказка пути не совпадёт под каталогом прошивки, и grab
    # сам найдёт функцию поиском по исходникам ядра — ровно для этого он так и устроен.
    ("src/crypto.cpp", "char* fmtUdeg("),
    ("src/tdeck_gps.cpp", "static int32_t nmeaCoord("),
)

HOST_EXTRA_MAIN = r"""
    // Координаты идут по сети и на экран целыми числами: во float девять значащих цифр
    // не помещаются. Проверяем обе стороны пути — печать микроградусов и разбор NMEA, —
    // потому что ошибка тут не падает, а тихо сдвигает точку на карте.
    struct { int32_t v; const char* want; } coords[] = {
        { 55751244,  "55.751244" },
        { -37618423, "-37.618423" },
        { 423,       "0.000423" },      // ведущие нули дробной части не теряются
        { 0,         "0.000000" },
        { 180000000, "180.000000" },
    };
    for (size_t i = 0; i < sizeof(coords) / sizeof(coords[0]); i++) {
        char b[20];
        memset(b, 'X', sizeof(b));
        fmtUdeg(coords[i].v, b, sizeof(b));
        if (strcmp(b, coords[i].want)) {
            printf("fmtUdeg: %ld -> %s, ждали %s\n", (long)coords[i].v, b, coords[i].want);
            return 1;
        }
    }
    struct { const char* in; int32_t want; } nmea[] = {
        { "4807.038",    48117300 },    // 48 07.038' — пример из стандарта
        { "5545.07464",  55751244 },    // та же точка, что у fmtUdeg выше
        { "03737.10538", 37618423 },    // долгота: три цифры градусов
        { "",            0 },
        { "abc",         0 },
        { "4860.0000",   0 },           // больше 60 минут не бывает
    };
    for (size_t i = 0; i < sizeof(nmea) / sizeof(nmea[0]); i++) {
        int32_t got = nmeaCoord(nmea[i].in);
        if (got != nmea[i].want) {
            printf("nmeaCoord(\"%s\") = %ld, ждали %ld\n", nmea[i].in,
                   (long)got, (long)nmea[i].want);
            return 1;
        }
    }
"""

HOST_EXTRA_LABEL = ("fmtUdeg", "nmeaCoord")


# ===== Приложение, которое движется само =====
def app_frame_ms_test(ctx):
    """Приложение может просить частый кадр, а оболочка его даёт — но не быстрее предела.

    До этого кадр просили раз в полсекунды, и ни одно приложение не могло двигаться само:
    игра шла бы двумя кадрами в секунду. Просит теперь само приложение — пятой, НЕ
    ОБЯЗАТЕЛЬНОЙ точкой входа appFrameMs: знать, что внутри движется, может только оно.
    Необязательность важна не меньше самой возможности: календарь и заметки собраны без
    неё, и требовать её от всех значило бы сломать уже собранные приложения.

    Нижний предел ставит оболочка: вывод кадра занимает шину SPI, общую с радио, и просить
    кадры чаще, чем панель успевает их принимать, значит отнимать эфир у приёма."""
    api = ctx.root / "include" / "tdeck_api.h"
    apps_h = ctx.root / "include" / "tdeck_apps.h"
    elf = ctx.root / "src" / "tdeck_elf.cpp"
    ui = ctx.root / "src" / "tdeck_ui.cpp"
    if not (api.is_file() and apps_h.is_file() and elf.is_file() and ui.is_file()):
        ctx.note("     SKIP app_frame_ms_test: исходников T-Deck рядом нет")
        return
    api_t, apps_t, elf_t, ui_t = (f.read_text(encoding="utf-8")
                                  for f in (api, apps_h, elf, ui))

    ctx.check("точка входа шага кадра объявлена в АБИ",
              re.search(r"(?m)^uint16_t\s+appFrameMs\s*\(\s*\)\s*;", api_t) is not None,
              "appFrameMs нет в tdeck_api.h — приложению нечем попросить кадр, и ни одна "
              "анимация в приложении невозможна")
    ctx.check("реестр хранит шаг кадра приложения",
              "frameMs" in apps_t,
              "в структурах реестра нет поля шага кадра: оболочке неоткуда его взять")
    ctx.check("загрузчик считает шаг кадра необязательным",
              re.search(r'\{\s*"appFrameMs"[^}]*true\s*\}', elf_t) is not None
              and re.search(r"optional", elf_t) is not None,
              "appFrameMs требуется наравне с остальными: уже собранные приложения "
              "(календарь, заметки) перестанут грузиться")
    ctx.check("обязательные точки входа остались обязательными",
              re.search(r'\{\s*"appDraw"[^}]*false\s*\}', elf_t) is not None,
              "appDraw помечен необязательным — приложение без рисования загрузится и "
              "упадёт при первом кадре")
    ctx.check("оболочка спрашивает шаг у ОТКРЫТОГО приложения",
              re.search(r"tdeckAppFrameMs\(\s*curApp\s*\)", ui_t) is not None,
              "шаг кадра берётся не у открытого приложения: частый кадр нужен тому, что "
              "сейчас на экране, а шина у платы одна")
    ctx.check("шаг кадра ограничен снизу",
              re.search(r"want\s*<\s*\(uint16_t\)TDECK_ANIM_FRAME_MS", ui_t) is not None,
              "предела нет: приложение сможет попросить кадр каждую миллисекунду и займёт "
              "шину SPI, общую с радио")
    sym = (ctx.root / "src" / "tdeck_symtab.cpp").read_text(encoding="utf-8")
    ctx.check("приложению доступны часы",
              re.search(r'S\("millis"', sym) is not None,
              "millis не экспортирован: движение приложению придётся считать по кадрам, а "
              "кадр может задержаться или прийти дважды")


# ===== Правила самой игры =====
# Ход змейки — это не рисование, а правила, и проверяются они счётом, а не картинкой:
# код хода вырезается из приложения и прогоняется на хосте под санитайзерами.
SNAKE_MAIN = r"""
static int fails = 0;
static void expect(bool ok, const char* what) {
    if (!ok) { printf("не сошлось: %s\n", what); fails++; }
}

static void put(int len, const int* xs, const int* ys) {
    bodyLen = len;
    for (int i = 0; i < len; i++) body[i] = cellOf(xs[i], ys[i]);
}

int main() {
    // Обычный ход: голова сдвинулась, длина не изменилась. Именно здесь была ошибка,
    // которую показал предпросмотр: змейка укорачивалась на звено за ход и исчезала.
    {
        const int xs[4] = {5, 4, 3, 2}, ys[4] = {5, 5, 5, 5};
        put(4, xs, ys);
        dirX = 1; dirY = 0; wantX = 1; wantY = 0;
        food = cellOf(20, 20);
        expect(stepOnce(), "обычный ход проходит");
        expect(bodyLen == 4, "длина при обычном ходе не меняется");
        expect(body[0] == cellOf(6, 5), "голова сдвинулась по направлению");
        // Хвост подтянулся: последнее звено встало туда, где было предпоследнее, а самая
        // дальняя клетка (2,5) освободилась — именно так змейка и движется.
        expect(body[3] == cellOf(3, 5), "хвост подтянулся");
    }
    // Яблоко: длина растёт ровно на звено, счёт на единицу.
    {
        const int xs[3] = {5, 4, 3}, ys[3] = {5, 5, 5};
        put(3, xs, ys);
        dirX = 1; dirY = 0; wantX = 1; wantY = 0;
        food = cellOf(6, 5);
        score = 0;
        expect(stepOnce(), "ход на яблоко проходит");
        expect(bodyLen == 4, "съев яблоко, змейка выросла на звено");
        expect(score == 1, "счёт вырос");
    }
    // Стена: ход в край поля — конец партии, с любой стороны.
    {
        const int xs[2] = {0, 1}, ys[2] = {3, 3};
        put(2, xs, ys);
        dirX = -1; dirY = 0; wantX = -1; wantY = 0;
        expect(!stepOnce(), "ход в левую стену — проигрыш");
        const int xs2[2] = {COLS - 1, COLS - 2}, ys2[2] = {3, 3};
        put(2, xs2, ys2);
        dirX = 1; dirY = 0; wantX = 1; wantY = 0;
        expect(!stepOnce(), "ход в правую стену — проигрыш");
        const int xs3[2] = {4, 4}, ys3[2] = {0, 1};
        put(2, xs3, ys3);
        dirX = 0; dirY = -1; wantX = 0; wantY = -1;
        expect(!stepOnce(), "ход в верхнюю стену — проигрыш");
        const int xs4[2] = {4, 4}, ys4[2] = {ROWS - 1, ROWS - 2};
        put(2, xs4, ys4);
        dirX = 0; dirY = 1; wantX = 0; wantY = 1;
        expect(!stepOnce(), "ход в нижнюю стену — проигрыш");
    }
    // В себя: ход в собственное тело — проигрыш, а в клетку уходящего хвоста — нет.
    {
        const int xs[5] = {5, 5, 4, 4, 3}, ys[5] = {5, 4, 4, 5, 5};
        put(5, xs, ys);
        dirX = 0; dirY = 1; wantX = -1; wantY = 0;   // поворот влево, в своё же тело
        food = cellOf(20, 20);
        expect(!stepOnce(), "ход в собственное тело — проигрыш");
    }
    {
        // Голова входит в клетку ПОСЛЕДНЕГО звена: оно уйдёт этим же ходом, и это не
        // проигрыш — так устроены все змейки.
        const int xs[4] = {5, 5, 4, 4}, ys[4] = {5, 4, 4, 5};
        put(4, xs, ys);
        dirX = -1; dirY = 0; wantX = 0; wantY = 1;   // вниз, в клетку хвоста
        food = cellOf(20, 20);
        expect(stepOnce(), "ход в клетку уходящего хвоста — не проигрыш");
    }
    // Разворот на себя запрещён: заявка «назад» игнорируется, змейка идёт прежним курсом.
    {
        const int xs[3] = {5, 4, 3}, ys[3] = {5, 5, 5};
        put(3, xs, ys);
        dirX = 1; dirY = 0; wantX = -1; wantY = 0;   // попытка развернуться
        food = cellOf(20, 20);
        expect(stepOnce(), "разворот не убивает змейку");
        expect(body[0] == cellOf(6, 5), "разворот на себя не применяется");
    }
    // Ускорение с каждым яблоком, но не быстрее предела.
    {
        const int xs[2] = {5, 4}, ys[2] = {5, 5};
        stepMs = STEP_MS_MIN + 1;
        put(2, xs, ys);
        dirX = 1; dirY = 0; wantX = 1; wantY = 0;
        food = cellOf(6, 5);
        stepOnce();
        expect(stepMs == STEP_MS_MIN, "скорость упирается в предел, а не уходит за него");
    }
    if (fails == 0) printf("змейка: правила сошлись\n");
    return fails == 0 ? 0 : 1;
}
"""


def snake_rules_test(ctx):
    """Правила змейки проверяются счётом, а не картинкой.

    Игра — первое приложение T-Deck с собственными правилами: стена, своё тело, рост от
    яблока, запрет разворота на себя. Всё это считается, а не рисуется, поэтому и
    проверяется на хосте: код хода вырезается из приложения как есть и прогоняется под
    санитайзерами.

    Повод не теоретический. Первая версия хода укорачивала змейку на звено за ход (хвост
    снимался отдельно от сдвига тела), и через четыре хода от неё не оставалось ничего —
    на предпросмотре было видно пустое поле с одним яблоком."""
    app = ctx.root / "apps" / "snake" / "snake.cpp"
    if not app.is_file():
        ctx.note("     SKIP snake_rules_test: приложения apps/snake рядом нет")
        return
    src = app.read_text(encoding="utf-8")

    # Состояние приложения объявлено файловыми статиками — повторяем объявления, а код
    # хода берём из приложения как есть: проверять нужно его, а не копию.
    prelude = """#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#define CELL 10
"""
    for name in ("COLS", "ROWS", "BODY_MAX", "STEP_MS_START", "STEP_MS_MIN", "STEP_MS_DEC"):
        m = re.search(r"(?m)^#define\s+%s\s+(\d+)" % name, src)
        ctx.check("в приложении задано %s" % name, m is not None,
                  "константа %s не найдена — проверять правила не на чем" % name)
        if m is None:
            return
        prelude += "#define %s %s\n" % (name, m.group(1))
    prelude += """
static uint16_t body[BODY_MAX];
static int bodyLen = 0;
static int8_t dirX = 1, dirY = 0, wantX = 1, wantY = 0;
static uint16_t food = 0;
static int score = 0;
static uint32_t stepMs = STEP_MS_START;
static uint32_t steps = 0;
static void foodPlace() { food = (uint16_t)((food + 7u) % (COLS * ROWS)); }
"""
    for sig in ("static inline uint16_t cellOf(", "static inline int cellX(",
                "static inline int cellY(", "static bool stepOnce("):
        code = ctx.grab(app, sig)
        ctx.check("вырезан %s" % sig.split()[-1].rstrip("("), bool(code),
                  "не нашлась функция %s — правила проверить нечем" % sig)
        prelude += code + "\n"

    ok, out = ctx.host_run(prelude + SNAKE_MAIN, "snake.cpp", "правила змейки")
    if ok is None:
        return
    ctx.check("правила змейки сошлись", ok, out.strip()[:400])


# ===== Главный экран: карусель вместо сетки страниц =====
# Меню было сеткой плиток по шесть на страницу: вверх-вниз листались страницы, понять
# место в списке можно было только по точкам. Теперь это лента в один ряд — выделенная
# плитка всегда по центру экрана, соседние частично уезжают за края, ряд листается вбок
# с заворотом. Раскладка живёт в tdeck_ui_draw.cpp и задаёт три вещи сразу: рисование
# (drawHome), попадание пальцем (tdeckMenuHit) и навигацию (tdeckMenuStep) — числа в
# одном месте, поэтому проверка числит геометрию той же функцией, что рисует.
MENU_MAIN = r"""
#include <stdio.h>

static int fails = 0;
static void mcap(const char* what, int got, int want) {
    if (got != want) {
        printf("карусель: %s: получили %d, ждали %d\n", what, got, want);
        fails++;
    }
}
static void mccap(const char* what, int got) {
    if (!got) {
        printf("карусель: %s: ложь\n", what);
        fails++;
    }
}

int main() {
    const int W = 320, H = 240;
    // Страниц больше нет: pages всегда 1, pageOf всегда 0 — оболочка, которая листала
    // страницы, видит единственную. Вернись сетка — pages посчитает страницы и упадёт.
    mcap("pages всегда 1", tdeckMenuPages(W, H), 1);
    mcap("pageOf всегда 0", tdeckMenuPageOf(W, H, 5), 0);
    // Выделенная плитка стоит по центру оси экрана при любом выделении.
    for (int sel = 0; sel < 8; sel++)
        mcap("выделенная по центру", tileX(W, sel, sel), W / 2 - TILE / 2);
    // Соседние плитки — на шаг ленты по бокам, а не в клетках сетки.
    mcap("сосед справа на ROW_STEP", tileX(W, 3, 4) - tileX(W, 3, 3), ROW_STEP);
    mcap("сосед слева на ROW_STEP", tileX(W, 3, 3) - tileX(W, 3, 2), ROW_STEP);
    // Плитка, уехавшая за экран целиком, не рисуется и не ловит касание.
    mccap("дальняя плитка невидима", !tileVisible(W, 0, 8));
    mccap("сосед виден краем", tileVisible(W, 0, 1));
    // Касание: центр выделенной плитки возвращает её индекс, центр соседа — соседа,
    // щель между плитками и всё за пределами ленты — промах.
    const int cy = tileY(H) + TILE / 2;
    mcap("тап в центр выделенной", tdeckMenuHit(W, H, 3, W / 2, cy), 3);
    mcap("тап в центр соседа справа", tdeckMenuHit(W, H, 3, W / 2 + ROW_STEP, cy), 4);
    mcap("тап в щель между плитками",
         tdeckMenuHit(W, H, 3, tileX(W, 3, 3) + TILE + 12, cy), -1);
    mcap("тап ниже ленты",
         tdeckMenuHit(W, H, 3, W / 2, tileY(H) + TILE + 10), -1);
    mcap("тап в строку состояния", tdeckMenuHit(W, H, 3, W / 2, 10), -1);
    // Навигация: ±1 по горизонтали, заворот за края, вертикаль ничего не двигает
    // (рядов больше нет — в сетке drow переносил бы на нижнюю плитку).
    mcap("шаг вправо", tdeckMenuStep(W, H, 3, 1, 0), 4);
    mcap("шаг влево", tdeckMenuStep(W, H, 3, -1, 0), 2);
    mcap("заворот с первой на последнюю", tdeckMenuStep(W, H, 0, -1, 0), 7);
    mcap("заворот с последней на первую", tdeckMenuStep(W, H, 7, 1, 0), 0);
    mcap("drow вниз не двигает", tdeckMenuStep(W, H, 3, 0, 1), 3);
    mcap("drow вверх не двигает", tdeckMenuStep(W, H, 3, 0, -1), 3);
    mcap("выход за предел справа", tdeckMenuStep(W, H, 20, 1, 0), 1);
    mcap("выход за предел слева", tdeckMenuStep(W, H, -3, -1, 0), 7);
    if (fails == 0) printf("карусель: раскладка сошлась\n");
    return fails == 0 ? 0 : 1;
}
"""


def menu_carousel_test(ctx):
    """Главный экран — карусель плиток в один ряд, а не сетка страниц.

    Старая сетка была по шесть плиток на страницу: вверх-вниз листались страницы, и у
    каждой плитки было только экранное место. Карусель центрирует выделенную плитку,
    листается вбок с заворотом и не знает страниц вовсе. Геометрия живёт одной функцией
    с рисованием — проверяем её, а не повторяем числами."""
    draw = ctx.root / "src" / "tdeck_ui_draw.cpp"
    if not draw.is_file():
        ctx.note("     SKIP menu_carousel_test: исходника экрана нет")
        return
    src = draw.read_text(encoding="utf-8")

    # Константы ленты берём из того же файла, что рисует, — проверяем исходник, а не
    # свою копию чисел. Снова страницы — ROW_STEP исчезнет, и это уже падение.
    prelude = """#include <stdint.h>
#include <stdio.h>
"""
    for name in ("TILE", "COL_GAP", "ROW_STEP", "TILE_ICON_H", "MENU_TOP"):
        m = re.search(r"(?m)^#define\s+%s\b(.*)$" % name, src)
        ctx.check("в раскладке задан %s" % name, m is not None,
                  "константа %s не найдена — проверять карусель не на чем" % name)
        if m is None:
            return
        prelude += "#define %s%s\n" % (name, m.group(1))
    ui_h = ctx.root / "include" / "tdeck_ui.h"
    mt = ui_h.read_text(encoding="utf-8") if ui_h.is_file() else ""
    m = re.search(r"(?m)^#define\s+TDECK_BAR_H\b(.*)$", mt)
    ctx.check("высота строки состояния задана", m is not None,
              "TDECK_BAR_H не найден — вертикальную геометрию не на чем считать")
    if m is None:
        return
    prelude += "#define TDECK_BAR_H%s\n" % m.group(1)

    # tdeckAppCount на хосте нет — стаб на 8 приложений (3 встроенных + 5 установленных,
    # как в макете). Навигация и попадание от него зависят только через n.
    prelude += "static int tdeckAppCount() { return 8; }\n"

    # Порядок важен: tdeckMenuHit зовёт tileX/tileVisible/tileY, они должны быть
    # определены раньше. Сам g++ бы не дал вызвать необъявленную — статики идут первой.
    for sig in ("static int tileX(int screenW, int sel, int i)",
                "static bool tileVisible(int screenW, int sel, int i)",
                "static int tileY(int screenH)",
                "int tdeckMenuPages(int screenW, int screenH)",
                "int tdeckMenuPageOf(int screenW, int screenH, int index)",
                "int tdeckMenuHit(int screenW, int screenH, int sel, int x, int y)",
                "int tdeckMenuStep(int screenW, int screenH, int cur, int dcol, int drow)"):
        try:
            code = ctx.grab(draw, sig)
        except RuntimeError:
            ctx.check("вырезана %s" % sig.split("(")[0].split()[-1], False,
                      "функция не нашлась — раскладка вернулась к сетке?")
            return
        prelude += code + "\n"

    ok, out = ctx.host_run(prelude + MENU_MAIN, "menu.cpp", "карусель главного экрана")
    if ok is None:
        return
    ctx.check("карусель сошлась", ok, out.strip()[:400])


def board_power_guard_test(ctx):
    """Настройка питания периферии не может погасить плату, где этот пин питает всё.

    Случай из жизни: плата приехала 6 октября 2026, в secrets.json у неё стояло
    `vext_on: 0` (значение досталось от Heltec, где активный уровень шины датчиков LOW), и
    первая же настройка погасила экран. У T-Deck этим пином (GPIO10 BOARD_POWERON)
    питается ВСЯ плата — панель, радио, клавиатура и карта, — так что ноль превращает узел
    в кирпич с одной консолью по USB, из которой уже не видно, что случилось.

    Защита живёт в ядре и в ОДНОМ месте: и старт прошивки, и команда «cfg vext» ходят
    через vextApply. Два места разошлись бы на первой же правке, и защита работала бы в
    одном из них."""
    pio = ctx.root / "platformio.ini"
    appmain = ctx.root / "lib" / "meshcore" / "src" / "app_main.cpp"
    cfg = ctx.core / "src" / "appconfig.cpp"
    if not (pio.is_file() and appmain.is_file() and cfg.is_file()):
        ctx.note("     SKIP board_power_guard_test: исходников рядом нет")
        return
    pio_t, main_t, cfg_t = (f.read_text(encoding="utf-8") for f in (pio, appmain, cfg))

    ctx.check("плата объявлена питающейся через этот пин",
              re.search(r"-DVEXT_IS_BOARD_POWER=1", pio_t) is not None,
              "признак не выставлен: настройка vext=0 снова погасит плату целиком")
    ctx.check("питание применяется одним входом на старте",
              re.search(r"vextApply\(cfg\.vextOn\)", main_t) is not None,
              "старт прошивки дёргает пин сам, мимо защиты — настройка vext=0 погасит узел "
              "при первой же перезагрузке")
    ctx.check("команда настройки идёт тем же входом",
              re.search(r"vextApply\(cfg\.vextOn\)", cfg_t) is not None,
              "«cfg vext» дёргает пин сам: защита останется только на старте")
    guard = cfg_t[cfg_t.find("void vextApply("):]
    guard = guard[:guard.find("\n}\n") + 3] if "\n}\n" in guard else guard
    ctx.check("у платы с таким пином настройка не применяется",
              re.search(r"#if\s+VEXT_IS_BOARD_POWER", guard) is not None
              and re.search(r"digitalWrite\(VEXT_PIN,\s*VEXT_EN_ACTIVE\)", guard) is not None,
              "защиты нет: ноль в настройке снимет питание со всей платы")
    ctx.check("отказ применить настройку не молчит",
              re.search(r"if\s*\(!vextOn\)", guard) is not None
              and "Serial.printf" in guard,
              "настройка молча игнорируется: «я же выключил, а оно горит» потом не "
              "объяснить")


def panel_orientation_test(ctx):
    """Разворот панели — тот, что подтверждён живой платой, и его можно перевернуть флагом.

    Ландшафт у ST7789 получается сменой осей (MV) плюс отражением одной из них: MY даёт
    один поворот, MX — тот же вид вверх ногами. Пока платы не было, выбор был гаданием, и
    выбран был MY; приехавшая плата показала изображение перевёрнутым."""
    drv = ctx.root / "include" / "st7789.h"
    if not drv.is_file():
        ctx.note("     SKIP panel_orientation_test: драйвера панели рядом нет")
        return
    src = drv.read_text(encoding="utf-8")
    body = src[src.find("uint8_t _madctlValue()"):]
    body = body[:body.find("\n  }") + 4] if "\n  }" in body else body
    ctx.check("ландшафт собран подтверждённым отражением",
              re.search(r"#else\s*\n\s*return ST7789_MADCTL_MX \| ST7789_MADCTL_MV;", body)
              is not None,
              "по умолчанию панель разворачивается не тем отражением: на живой плате это "
              "изображение вверх ногами")
    ctx.check("разворот переключается флагом сборки",
              "TDECK_SCREEN_FLIP" in body and "TDECK_SCREEN_FLIP" in src,
              "флага разворота нет: у партии с иначе поставленной панелью придётся править "
              "драйвер")


def battery_pin_test(ctx):
    """Батарея меряется: пин и делитель заданы, иначе на экране вечный прочерк.

    Пока пин не был подтверждён, измерение не включали намеренно — выдуманные проценты
    хуже прочерка. Живая плата показала пустой корпус именно поэтому. У T-Deck VBAT
    приходит на ADC1_CH3 (GPIO4) через делитель 1:2."""
    pio = ctx.root / "platformio.ini"
    if not pio.is_file():
        ctx.note("     SKIP battery_pin_test: platformio.ini рядом нет")
        return
    t = pio.read_text(encoding="utf-8")
    ctx.check("пин батареи задан",
              re.search(r"(?m)^\s*-DPIN_VBAT_READ=4\b", t) is not None,
              "измерения батареи нет: экран покажет пустой корпус с прочерком, сколько бы "
              "заряда в аккумуляторе ни было")
    ctx.check("делитель батареи задан",
              re.search(r"-DPIN_VBAT_DIVIDER=2\.0f", t) is not None,
              "делитель не задан: ядро возьмёт значение Heltec (4.9), и напряжение выйдет "
              "вдвое с лишним больше настоящего")


def keyboard_probe_read_only_test(ctx):
    """Клавиатуру ищем чтением, а не записью.

    Клавиатура T-Deck — отдельный ESP32-C3 со своей прошивкой, и что она делает с
    полученной записью, мы не знаем. Пустая запись «есть ли кто по адресу» — тоже посылка
    на шину: после того, как опрос клавиатуры стал повторяться, у живой платы погасла
    подсветка клавиш. Чтение — ровно то, что прошивка делает в обычной работе, и оно
    заведомо безопасно.

    Проверка смотрит: в опросе клавиатуры нет записи, а чтение есть."""
    inp = ctx.root / "src" / "tdeck_input.cpp"
    if not inp.is_file():
        ctx.note("     SKIP keyboard_probe_read_only_test: слоя ввода рядом нет")
        return
    t = inp.read_text(encoding="utf-8")
    code = "\n".join((ln if ln.find("//") < 0 else ln[:ln.find("//")])
                      for ln in t.splitlines())
    # Писать в клавиатуру можно, но только ОСМЫСЛЕННУЮ команду её протокола (0x01 —
    # яркость, 0x02 — яркость для Alt+B). Пустая запись «есть ли кто по адресу» — это
    # посылка, которую чужая прошивка вольна понять как что угодно; именно после такой
    # у живой платы погасла подсветка клавиш. Поэтому проверяем не «не пишут вовсе», а
    # «каждая запись несёт байт команды».
    blind = []
    for m in re.finditer(r"Wire\.beginTransmission\(\s*\(?u?int8?_?t?\)?\s*TDECK_KBD_ADDR[^;]*;",
                         code):
        tail = code[m.end():m.end() + 200]
        if not re.search(r"Wire\.write\(\s*\(?uint8_t\)?\s*KBD_CMD_", tail):
            blind.append(m.group(0))
    ctx.check("в клавиатуру пишут только командой протокола", not blind,
              "есть запись в клавиатуру без байта команды: чужая прошивка вольна понять её "
              "как что угодно — так уже погасла подсветка клавиш")
    ctx.check("клавиатура ищется чтением",
              len(re.findall(r"Wire\.requestFrom\(\(int\)TDECK_KBD_ADDR", code)) >= 2,
              "чтения для поиска клавиатуры нет: либо её не найдут, либо найдут записью")
    ctx.check("общий обход шины обходит клавиатуру стороной",
              re.search(r"a\s*==\s*\(uint8_t\)TDECK_KBD_ADDR", code) is not None,
              "обход шины пишет во все адреса подряд, включая клавиатуру")
    ctx.check("подсветка клавиш включается прошивкой",
              "KBD_CMD_BRIGHTNESS" in code and "tdeckKeyboardBacklight" in code,
              "подсветку клавиш никто не зажигает: контроллер клавиатуры стартует с нулевой "
              "яркостью, и клавиши в темноте не видно")
    ctx.check("яркость для Alt+B задана прошивкой",
              "KBD_CMD_ALT_B_DEFAULT" in code,
              "контроллеру не сказано, какую яркость ставить по Alt+B: он вернёт свою "
              "половинную, а не ту, что светит на плате")
    ctx.check("клавиатуру ждут на старте и переспрашивают потом",
              "KBD_BOOT_WAIT_MS" in code and "KBD_REPROBE_MS" in code,
              "без ожидания контроллер клавиатуры (ESP32-C3 грузится около секунды) не "
              "успевает отозваться, и плата остаётся без клавиатуры до перезагрузки")


def status_clock_contrast_test(ctx):
    """Часы в строке состояния — белые и шрифтом значений.

    На макете мягкий COL_TEXT (#C7D5E0) на тёмной полосе читался нормально, на живой
    панели — нет: «часы почти не видно, они на заднем плане». Часы — единственное, что на
    этой полосе читают намеренно, и контраст им нужен полный."""
    draw = ctx.root / "src" / "tdeck_ui_draw.cpp"
    pal = ctx.root / "include" / "tdeck_palette.h"
    if not (draw.is_file() and pal.is_file()):
        ctx.note("     SKIP status_clock_contrast_test: рисования рядом нет")
        return
    d, p = draw.read_text(encoding="utf-8"), pal.read_text(encoding="utf-8")
    ctx.check("чистый белый есть в палитре",
              re.search(r"#define\s+COL_WHITE\s+0xFFFF", p) is not None,
              "белого в палитре нет: контраст придётся набирать случайными числами")
    ctx.check("часы рисуются белым",
              re.search(r"s\.clock\[0\]\)\s*textAtF\([^;]*COL_WHITE", d) is not None,
              "часы рисуются мягким цветом: на живой панели они сливаются с полосой")
    ctx.check("часы рисуются шрифтом значений",
              re.search(r"s\.clock\[0\]\)\s*textAtF\([^;]*FONT_VALUE", d) is not None,
              "часы мельче, чем нужно: на полосе 26 px они теряются среди пиктограмм")


def elf_iram_access_test(ctx):
    """Образ собирается в обычной памяти, а в исполняемую переносится СЛОВАМИ.

    Живая плата ушла в циклическую перезагрузку ровно на этом: память под образ наконец
    нашлась, загрузчик начал применять релокации прямо в ней — и упал с LoadStoreError по
    адресу в IRAM. Исполняемая память на ESP32-S3 отвечает только на 32-битные обращения,
    а сборка образа (копирование сегментов, релокации, чтение таблицы конструкторов) вся
    байтовая. Поэтому образ собирается в обычной памяти и переносится готовым, словами.

    Падение было на СТАРТЕ, в сканировании приложений, то есть повторялось бесконечно —
    отсюда же вторая половина проверки: имя загружаемого приложения кладётся в NVS до
    загрузки и снимается после, и приложение, чья загрузка не вернулась, в следующий раз
    пропускается. Плата обязана загружаться даже с заведомо плохим приложением на карте."""
    elf = ctx.root / "src" / "tdeck_elf.cpp"
    if not elf.is_file():
        ctx.note("     SKIP elf_iram_access_test: загрузчика рядом нет")
        return
    t = elf.read_text(encoding="utf-8")
    code = "\n".join((ln if ln.find("//") < 0 else ln[:ln.find("//")])
                      for ln in t.splitlines())

    # Одна память, два окна. Живая плата прошла через ОБА падения подряд, и проверка
    # держит именно их: сначала LoadStoreError (образ собирали по адресу окна команд, а
    # байтовый доступ там запрещён), потом InstructionFetchError (всё перевели в окно
    # данных, включая точки входа, и процессор пошёл выполнять код из окна данных).
    ctx.check("образ собирается по адресу окна данных",
              "MAP_IRAM_TO_DRAM" in code,
              "образ собирается по адресу окна команд: любое байтовое обращение к нему "
              "(релокация, строка, статика) роняет узел LoadStoreError")
    ctx.check("переход в окно данных сверяется с диапазоном",
              re.search(r"SOC_DIRAM_IRAM_LOW", code) is not None
              and re.search(r"SOC_DIRAM_IRAM_HIGH", code) is not None,
              "адрес переводится в другое окно без проверки диапазона: окно данных есть "
              "только у совмещённой области, промах — это запись мимо своей памяти")
    ctx.check("релокации считаются под окно данных",
              re.search(r"base\s*=\s*\(uint32_t\)\(uintptr_t\)mem", code) is not None,
              "адреса данных приложения пересчитаны под окно команд — байтовое чтение "
              "собственных строк уронит приложение")
    ctx.check("точки входа считаются под окно команд",
              len(re.findall(r"lo,\s*deltaExec,", code)) >= 2,
              "точки входа пересчитаны под окно данных: процессор пойдёт выполнять код "
              "оттуда и упадёт InstructionFetchError")
    ctx.check("конструкторы зовутся через окно команд",
              re.search(r"addr\s*=\s*\(uint32_t\)\(\(int32_t\)addr\s*-\s*delta\s*\+\s*deltaExec\)",
                        code) is not None,
              "конструктор зовётся по адресу окна данных — то же падение, только раньше")

    # --- защита от приложения, которое роняет плату ---
    ctx.check("имя приложения отмечается в NVS до загрузки",
              "elfMarkLoading(" in code and "Preferences" in t,
              "нет отметки о начатой загрузке: приложение, роняющее узел, будет ронять его "
              "на каждом старте — плата уходит в циклическую перезагрузку")
    ctx.check("отметка снимается после возврата",
              re.search(r'elfMarkLoading\(""\)', code) is not None,
              "отметка не снимается: после первой же успешной загрузки приложение будет "
              "считаться опасным и больше не запустится")
    ctx.check("опасное приложение пропускается",
              re.search(r"strcmp\(elfBlocked,\s*apps\[i\]\.folder\)", code) is not None,
              "отметка есть, а пропуска нет: плата всё равно повторит падение")


def apps_relative_data_only_test(ctx):
    """Внутренние переходы в приложениях относительные: в коде нет пересчитываемых адресов.

    На этом стоит вся схема загрузки: образ живёт в одной памяти, но работает через два
    окна — данные читаются по адресу окна данных, код выполняется по адресу окна команд.
    Это допустимо ровно потому, что приложение не хранит адресов СВОЕГО КОДА: внутренние
    вызовы у него относительные (call8), а через литералы идут только вызовы наружу, чьи
    адреса приходят из экспортной таблицы прошивки.

    Проверка читает настоящие собранные приложения и смотрит каждую релокацию типа
    RELATIVE: куда указывает значение, лежащее в месте релокации. Хоть одно попадание в
    текстовую секцию — и схему надо менять (придётся разносить код и данные по разным
    блокам), поэтому лучше узнать об этом здесь, чем по панике на плате."""
    import struct as _st
    apps = sorted((ctx.root / "apps").glob("*/*.elf"))
    if not apps:
        ctx.note("     SKIP apps_relative_data_only_test: собранных приложений рядом нет")
        return
    R_XTENSA_RELATIVE = 5
    for elf in apps:
        b = elf.read_bytes()
        if len(b) < 64 or b[:4] != b"\x7fELF":
            ctx.check("приложение %s читается" % elf.parent.name, False, "это не ELF")
            continue
        e_shoff, = _st.unpack_from("<I", b, 0x20)
        e_shentsize, e_shnum, e_shstrndx = _st.unpack_from("<HHH", b, 0x2E)
        secs = []
        for i in range(e_shnum):
            o = e_shoff + i * e_shentsize
            nm, typ, flags, addr, off, size = _st.unpack_from("<6I", b, o)
            secs.append(dict(nm=nm, typ=typ, flags=flags, addr=addr, off=off, size=size))
        sh = secs[e_shstrndx]
        for s in secs:
            end = b.index(b"\0", sh["off"] + s["nm"])
            s["name"] = b[sh["off"] + s["nm"]:end].decode(errors="replace")
        text = [s for s in secs if s["flags"] & 0x4]          # SHF_EXECINSTR
        rela = [s for s in secs if s["name"] == ".rela.dyn"]
        if not text or not rela:
            ctx.check("у %s есть код и релокации" % elf.parent.name, False,
                      "нет текстовой секции или .rela.dyn")
            continue
        tlo = min(s["addr"] for s in text)
        thi = max(s["addr"] + s["size"] for s in text)
        bad = 0
        for i in range(rela[0]["size"] // 12):
            off, info, add = _st.unpack_from("<III", b, rela[0]["off"] + i * 12)
            if (info & 0xFF) != R_XTENSA_RELATIVE:
                continue
            src = [s for s in secs if s["typ"] != 8 and s["addr"] <= off < s["addr"] + s["size"]]
            if not src:
                continue
            val, = _st.unpack_from("<I", b, src[0]["off"] + (off - src[0]["addr"]))
            if tlo <= val < thi:
                bad += 1
        ctx.check("%s: пересчитываемых адресов кода нет" % elf.parent.name, bad == 0,
                  "в приложении %d адрес(ов) собственного кода хранится в данных: при "
                  "загрузке они укажут в окно данных, и первый же вызов уронит узел "
                  "InstructionFetchError" % bad)


def wifi_switch_test(ctx):
    """Выключатель радио и показ набранного знака пароля.

    Выключатель: радио Wi-Fi узлу нужно не всегда, а выключенным оно не тратит ток и не
    будит плату попытками переподключиться. Состояние обязано пережить перезагрузку —
    иначе выключенная сеть возвращается сама, и выключатель ничего не значит.

    Пароль: вслепую, сразу звёздочкой, непонятно, что именно нажалось, — клавиатура у
    платы мелкая. Последний знак показывается открытым короткое время, как в телефоне.

    Рисование при этом про радио по-прежнему ничего не знает: оно читает состояние из
    кадра и кладёт ПРОСЬБУ переключить, а переключает прошивочная часть. Иначе тот же
    файл не собрался бы в макет экрана на настольной машине, где Wi-Fi нет вовсе."""
    apps = ctx.root / "src" / "tdeck_apps.cpp"
    wifi = ctx.root / "src" / "tdeck_wifi.cpp"
    ui = ctx.root / "src" / "tdeck_ui.cpp"
    if not (apps.is_file() and wifi.is_file() and ui.is_file()):
        ctx.note("     SKIP wifi_switch_test: исходников T-Deck рядом нет")
        return
    a, w, u = (f.read_text(encoding="utf-8") for f in (apps, wifi, ui))

    ctx.check("выключатель радио есть в прошивочной части",
              "void tdeckWifiSetEnabled" in w and "bool tdeckWifiEnabled" in w,
              "радио нечем выключить: раздел сети сможет только искать и подключаться")
    ctx.check("состояние выключателя переживает перезагрузку",
              "Preferences" in w and re.search(r'putBool\(WIFI_NVS_KEY', w) is not None,
              "состояние не сохраняется: выключенная сеть вернётся сама при первом же "
              "включении платы")
    ctx.check("выключенное радио не поднимается само",
              re.search(r"void tdeckWifiBegin\(\)\s*\{[^}]*tdeckWifiEnabled", w) is not None,
              "старт прошивки поднимает радио мимо выключателя")
    ctx.check("рисование не трогает радио напрямую",
              "tdeckWifiSetEnabled" not in a,
              "раздел сети зовёт радио из рисования: тот же файл собирается в макет экрана "
              "на настольной машине, где радио нет")
    ctx.check("переключение идёт просьбой",
              "tdeckWifiToggleRequested" in a and "tdeckWifiToggleRequested" in u,
              "просьбы переключить нет: выключатель нарисован, а нажатие ничего не делает")
    ctx.check("состояние выключателя приходит в кадре",
              re.search(r"(?m)^\s*bool\s+wifiEnabled;",
                        (ctx.root / "include" / "tdeck_ui.h").read_text(encoding="utf-8"))
              is not None and "s->wifiEnabled" in a,
              "рисование не видит состояния радио и покажет выключатель наугад")
    ctx.check("включение сразу ищет сети",
              re.search(r"tdeckWifiSetEnabled\(on\);\s*\n\s*if \(on\) tdeckWifiScan\(\)", u)
              is not None,
              "после включения список сетей остаётся пустым до отдельного действия")

    # Заход в раздел при живом подключении обязан показывать АДРЕС: за ним сюда и
    # заходят. Плата, подключившаяся к сохранённой сети сама, иначе не показывала его
    # вовсе — заход всегда открывал список и запускал поиск.
    ctx.check("подключённая плата показывает адрес сразу",
              re.search(r"lastState\.wifiState == 3 \|\| lastState\.wifiState == 2",
                        a) is not None,
              "заход в раздел всегда открывает список: у автоматически подключённой платы "
              "адрес увидеть негде")
    ctx.check("при выключенном радио поиск не запускается",
              re.search(r"!lastState\.wifiEnabled\) return;", a) is not None,
              "заход в раздел с выключенным радио просит поиск: искать нечем, и список "
              "останется пустым с бесполезной надписью")

    # Веб-интерфейс — это открытый порт на плате. Выключили радио — он обязан закрыться,
    # и зависеть это должно от самого выключателя, а не от того, успело ли обновиться
    # состояние подключения.
    web = ctx.root / "src" / "tdeck_web.cpp"
    if web.is_file():
        wt = web.read_text(encoding="utf-8")
        ctx.check("веб-интерфейс закрывается вместе с радио",
                  re.search(r"tdeckWifiEnabled\(\)\s*&&\s*tdeckWifiState\(\)\s*==\s*TWIFI_ONLINE",
                            wt) is not None,
                  "сервер держится только на состоянии подключения: при выключенном радио "
                  "порт останется открытым, пока состояние не обновится")
        ctx.check("остановка сервера называет причину",
                  re.search(r"Wi-Fi выключен", wt) is not None,
                  "в журнале не отличить «нет адреса» от «радио выключено» — а чинят их "
                  "по-разному")

    # --- пароль ---
    ctx.check("последний знак пароля показывается открытым",
              "PASS_REVEAL_MS" in a and re.search(r"shown\[n - 1\]\s*=\s*wifiPassBuf\[n - 1\]", a)
              is not None,
              "пароль сразу закрывается звёздочками: на мелкой клавиатуре не видно, что "
              "именно нажалось")
    ctx.check("открытый знак прячется по времени, а не по событию",
              re.search(r"millis\(\) - wifiPassCharMs\) < PASS_REVEAL_MS", a) is not None
              and re.search(r"wifiPassCharMs != 0", a) is not None,
              "знак прячется только на следующем нажатии: убрал руки — и он остался на "
              "экране открытым")
    ctx.check("кадр обновляется, когда знак прячется",
              re.search(r"age / 100u", a) is not None,
              "признак кадра не меняется со временем: звёздочка появится не по времени, а "
              "по следующему событию — то есть может не появиться вовсе")


def snake_moves_test(ctx):
    """Змейка двигается сама: в признаке кадра есть время.

    Круг замыкался так: ход считается внутри рисования, рисование оболочка просит только
    при изменении признака кадра, а признак меняется ходом. Первый кадр нарисовался — и
    всё замерло. На живой плате это выглядело как «змейка стоит на месте».

    Поэтому пока партия идёт, в признак входит номер текущего шага по часам: наступил
    срок хода — признак сменился — оболочка просит кадр — в кадре случается ход. На паузе
    и после проигрыша время из признака уходит: там ничего не движется."""
    app = ctx.root / "apps" / "snake" / "snake.cpp"
    if not app.is_file():
        ctx.note("     SKIP snake_moves_test: приложения apps/snake рядом нет")
        return
    body = ctx.grab(app, "uint32_t appFrameKey(")
    code = "\n".join((ln if ln.find("//") < 0 else ln[:ln.find("//")])
                      for ln in body.splitlines())
    ctx.check("в признаке кадра есть время партии",
              re.search(r"millis\(\)\s*/\s*stepMs", code) is not None,
              "признак кадра не зависит от времени: ход считается в рисовании, а рисование "
              "просят по изменению признака — игра замрёт после первого кадра")
    ctx.check("время входит в признак только на ходу игры",
              re.search(r"state\s*==\s*ST_PLAY", code) is not None,
              "время в признаке и на паузе: плата будет перерисовывать неподвижный экран "
              "по десять раз в секунду")
    ms = ctx.grab(app, "uint16_t appFrameMs(")
    ctx.check("частый кадр просится только на ходу игры",
              re.search(r"state\s*!=\s*ST_PLAY\)\s*return 0", ms) is not None,
              "частый кадр просится всегда: шина SPI общая с радио, и неподвижный экран "
              "отнимал бы приём")


def touch_calibration_test(ctx):
    """Оси касания подбираются НА ПЛАТЕ и запоминаются.

    Как ложатся оси тачскрина на оси изображения — свойство конкретной платы: зависит и
    от разворота панели, и от того, как на ней стоит сам тачскрин. На живой плате подряд
    не сошлись два «правильных» по документации варианта, и каждый следующий означал
    новую сборку и новую прошивку. Поэтому преобразование — не макросы, а три числа,
    которые подбираются касанием двух углов и живут в NVS.

    Два угла, а не один: по одному раскладки «оси повёрнуты» и «оси зеркальны» не
    различаются. Перебор всех восьми раскладок с выбором ближайшей — это и есть ответ
    платы за себя саму, вместо нашего гадания."""
    inp = ctx.root / "src" / "tdeck_input.cpp"
    apps = ctx.root / "src" / "tdeck_apps.cpp"
    if not (inp.is_file() and apps.is_file()):
        ctx.note("     SKIP touch_calibration_test: исходников рядом нет")
        return
    i, a = inp.read_text(encoding="utf-8"), apps.read_text(encoding="utf-8")

    ctx.check("оси касания — величины, а не макросы",
              re.search(r"static uint8_t touchSwap\s*=", i) is not None
              and re.search(r"static uint8_t touchFlipX\s*=", i) is not None,
              "оси зашиты макросами: поправить их можно только новой сборкой и прошивкой")
    # Поворотов и зеркал мало: панель вправе сообщать координаты в СВОЁМ диапазоне, и
    # тогда ни одна из восьми раскладок не ложится — живая плата отвечала «try again» на
    # любую попытку. Поэтому считается настоящее линейное преобразование по трём точкам.
    ctx.check("подбор считает масштаб, а не только повороты",
              re.search(r"bool tdeckTouchCalibrate3", i) is not None
              and re.search(r"touchKx\s*=\s*\(int16_t\)", i) is not None,
              "подбор умеет только поворот и зеркала: панель с другим диапазоном сырых "
              "координат так не описывается, и подбор всегда будет отвечать «ещё раз»")
    ctx.check("поворот осей определяется ходом пальца",
              re.search(r"abs\(dAy\) > abs\(dAx\)", i) is not None,
              "поворот осей угадывается, а не измеряется: от первой мишени ко второй палец "
              "идёт только по горизонтали, и этого достаточно, чтобы его узнать")
    ctx.check("короткий ход сырых осей отвергается",
              re.search(r"abs\(hx\) < 16 \|\| abs\(vy\) < 16", i) is not None,
              "подбор делит на ход осей без проверки: касание мимо мишеней даст деление на "
              "почти ноль и запишет мусор")
    ctx.check("подобранное переживает перезагрузку",
              re.search(r'putShort\("kx"', i) is not None
              and re.search(r'putUChar\("aff"', i) is not None,
              "преобразование не сохраняется: после перезагрузки экран снова не слушается "
              "пальца")
    ctx.check("результат сверяется на точках подбора",
              re.search(r"return err <= 50", i) is not None,
              "подбор принимает любой результат: касание мимо мишеней запишет заведомо "
              "неверное преобразование, и экран станет хуже, чем был")
    ctx.check("преобразование не выпускает палец за экран",
              re.search(r"sx >= SCREEN_WIDTH", i) is not None,
              "неточный подбор отправит касание за границы экрана — это промах по всем "
              "плиткам сразу")
    ctx.check("подбор идёт по трём точкам",
              re.search(r"touchRx\[3\]", a) is not None
              and re.search(r"touchTargetPos", a) is not None,
              "точек меньше трёх: по двум диагональным углам поворот осей и зеркала "
              "неразличимы, а масштаб не вычислить")
    # Разбор ответа панели: запись точки начинается С КООРДИНАТЫ. Живая плата сообщала
    # «6144, 11008, 9984» — ровные кратные 256, чего у настоящих координат не бывает:
    # читался старший байт X вместе с младшим байтом Y, то есть со сдвигом на байт.
    ctx.check("координаты точки читаются с начала записи",
              re.search(r"rx = p\[0\] \| \(p\[1\] << 8\)", i) is not None
              and re.search(r"ry = p\[2\] \| \(p\[3\] << 8\)", i) is not None,
              "запись точки читается со сдвигом: в координаты попадут чужие байты, и "
              "касание будет промахиваться мимо всего")

    ctx.check("калибровка берёт СЫРЫЕ координаты",
              "tdeckTouchLastRaw" in a,
              "подбор считает по экранным координатам, которые сам же и должен исправить")
    ctx.check("в настройках есть раздел касания",
              "SET_TOUCH" in a and re.search(r'return "Touch"', a) is not None,
              "подбор некуда вызвать: раздел в списке настроек отсутствует")
    ctx.check("мишени стоят по осям, а не по диагонали",
              re.search(r"x = TOUCH_TARGET_PAD;\s+y = TOUCH_TARGET_TOP", a) is not None
              and re.search(r"x = W - TOUCH_TARGET_PAD;\s+y = TOUCH_TARGET_TOP", a) is not None
              and re.search(r"y = H - TOUCH_TARGET_PAD", a) is not None,
              "мишени расставлены иначе: ход пальца между первой и второй обязан быть "
              "чисто горизонтальным, между первой и третьей — чисто вертикальным")
