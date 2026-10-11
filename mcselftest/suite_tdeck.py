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
# с заворотом. Боковые плитки мельче центральной, чтобы по каждую руку влезало по две.
# Раскладка живёт в tdeck_ui_draw.cpp и задаёт три вещи сразу: рисование (drawHome),
# попадание пальцем (tdeckMenuHit) и навигацию (tdeckMenuStep) — числа в одном месте,
# поэтому проверка числит геометрию той же функцией, что рисует.
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
// Дробный левый край плитки в целых пикселях.
static int mf(int selF10, int i) {
    float f = tileXf(320.0f, (float)selF10 / 10.0f, i);
    return (int)(f + (f >= 0 ? 0.5f : -0.5f));
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
    // Соседние плитки — на ход ленты по бокам, а не в клетках сетки. Ходы по центрам:
    // ±1 на STEP1, ±2 на ещё STEP2 (ходит центр, края уезжают на разницу размеров).
    mcap("центр ±1 справа на STEP1", tileX(W, 3, 4) + TILE_S1 / 2 - (tileX(W, 3, 3) + TILE / 2), STEP1);
    mcap("центр ±1 слева на STEP1", tileX(W, 3, 3) + TILE / 2 - (tileX(W, 3, 2) + TILE_S1 / 2), STEP1);
    mcap("центр ±2 на STEP1+STEP2", tileX(W, 3, 5) + TILE_S2 / 2 - (tileX(W, 3, 4) + TILE_S1 / 2), STEP2);
    // Левые края ленты на 320 пикселях: ±2 почти упираются в края экрана (3..69 и 251..317).
    mcap("левый край ±2 слева", tileX(W, 3, 1), W / 2 - (STEP1 + STEP2) - TILE_S2 / 2);
    mcap("левый край ±2 справа", tileX(W, 3, 5), W / 2 + (STEP1 + STEP2) - TILE_S2 / 2);
    // Все четыре боковые плитки видны на 320 пикселях, дальше пары шагов — нет.
    mccap("±1 слева видна", tileVisible(W, 3, 2));
    mccap("±1 справа видна", tileVisible(W, 3, 4));
    mccap("±2 слева видна", tileVisible(W, 3, 1));
    mccap("±2 справа видна", tileVisible(W, 3, 5));
    mccap("дальше пары шагов не видна", !tileVisible(W, 3, 0));
    mccap("дальше пары шагов справа не видна", !tileVisible(W, 3, 6));
    // Заворот: дальняя плитка круга — по-настоящему ближний сосед.
    mccap("заворот: сосед через край виден", tileVisible(W, 0, 7));
    // Промежуточный кадр проворота: полшага — правый край на полхода вправо, левый влево,
    // размер — средний между раскладками.
    mcap("промежуточный кадр: размер на полшага",
         (int)(tileSizeF(0.5f) + 0.5f), (TILE + TILE_S1) / 2);
    mcap("промежуточный кадр: правая на полхода", mf(35, 4) + (TILE + TILE_S1) / 4,
         W / 2 + STEP1 / 2);
    mcap("промежуточный кадр: левая на полхода", mf(35, 3) + (TILE + TILE_S1) / 4,
         W / 2 - STEP1 / 2);
    // На целом шаге дробная раскладка сходится с целой.
    mcap("дробный край на целом шаге", mf(30, 4), tileX(W, 3, 4));
    // Заворот едет через край: выделение 7→0 — плитка 0 приезжает справа, 7 уходит влево.
    mcap("заворот: плитка 0 на полшага справа", mf(75, 0) + (TILE + TILE_S1) / 4,
         W / 2 + STEP1 / 2);
    mcap("заворот: плитка 7 на полшага слева", mf(75, 7) + (TILE + TILE_S1) / 4,
         W / 2 - STEP1 / 2);
    // Касание: центры плиток возвращают свои индексы, за пределами ленты — промах.
    // Координаты из той же геометрии: центр ±1 на STEP1, ±2 на STEP1+STEP2.
    const int cy = tileY(H) + TILE / 2;
    mcap("тап в центр выделенной", tdeckMenuHit(W, H, 3, W / 2, cy), 3);
    mcap("тап в центр ±1 справа", tdeckMenuHit(W, H, 3, W / 2 + STEP1, cy), 4);
    mcap("тап в центр ±1 слева", tdeckMenuHit(W, H, 3, W / 2 - STEP1, cy), 2);
    mcap("тап в центр ±2 справа", tdeckMenuHit(W, H, 3, W / 2 + STEP1 + STEP2, cy), 5);
    mcap("тап в центр ±2 слева", tdeckMenuHit(W, H, 3, W / 2 - STEP1 - STEP2, cy), 1);
    // Заворот показывают и касания: с выделенной первой плитки сосед слева — последняя.
    mcap("тап в ±1 слева через заворот", tdeckMenuHit(W, H, 0, W / 2 - STEP1, cy), 7);
    mcap("тап ниже ленты", tdeckMenuHit(W, H, 3, W / 2, tileY(H) + TILE + 10), -1);
    mcap("тап над лентой", tdeckMenuHit(W, H, 3, W / 2, TDECK_BAR_H + MENU_TOP - 1), -1);
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
    // Проворот живёт не только кадрами, но и путём: заворот едет через край короткой
    // дорогой — с первой плитки влево через виртуальную −1 (последняя приезжает слева),
    // с последней вправо через виртуальную n (первая приезжает справа). Полный круг на
    // экране выглядит как «вернулось в центр»: лента проезжает всю окружность и ложится,
    // как лежала, а выделение дёргается на своё место.
    curSel = 0;
    menuScrollStart(tdeckMenuStep(W, H, 0, -1, 0));
    mcap("заворот влево: путь через −1", (int)menuScrollTo, -1);
    curSel = 7;
    menuScrollStart(tdeckMenuStep(W, H, 7, 1, 0));
    mcap("заворот вправо: путь через n", (int)menuScrollTo, 8);
    curSel = 3;
    menuScrollStart(tdeckMenuStep(W, H, 3, -1, 0));
    mcap("шаг влево: сосед, не заворот", (int)menuScrollTo, 2);
    menuScrollStart(tdeckMenuStep(W, H, 3, 1, 0));
    mcap("шаг вправо: сосед, не заворот", (int)menuScrollTo, 4);
    // Проворот живёт кадрами: первый кадр — единица, дальше растёт, по истечении — ноль.
    mcap("проворот: первый кадр фаза 1", menuScrollPhaseOf(0), 1);
    mcap("проворот: кадр на шаге анимации", menuScrollPhaseOf(TDECK_ANIM_FRAME_MS), 2);
    mcap("проворот: кончился — фаза 0", menuScrollPhaseOf(TDECK_SCROLL_MS), 0);

    // ===== Подписи плиток =====
    // Они живут ПОД лентой общей строкой. Внутри плиток их держать нельзя: лента уходит
    // клином, соседняя плитка заходит под выделенную на (TILE - TILE_S1)/2 + (TILE_S1 -
    // STEP1) пикселей, и центрированная подпись соседа уезжала под неё обрубком
    // («Senso», «otes»). Убрать их у соседей тоже не вышло — имя пропадало на глазах,
    // стоило ленте тронуться. Поэтому проверяем ровно три обещания раскладки: подпись
    // есть у КАЖДОЙ видимой плитки, подписи не налезают друг на друга, и выделенной
    // место достаётся целиком.
    {
        // Пять плиток ленты в покое: расстояния −2…+2, выделенная в середине массива.
        const float sd5[5] = { -2.0f, -1.0f, 0.0f, 1.0f, 2.0f };
        // Имена пошире настоящих: «Settings» в шрифте интерфейса около 55 пикселей.
        int want5[5] = { 60, 60, 60, 60, 60 };
        MenuCap c5[5];
        menuCapLayout(W, sd5, want5, 5, 2, c5);
        for (int k = 0; k < 5; k++) {
            char what[128];
            snprintf(what, sizeof(what), "подпись %d есть", k);
            mccap(what, c5[k].w >= MENU_CAP_MIN);
            snprintf(what, sizeof(what), "подпись %d на экране", k);
            mccap(what, c5[k].x >= MENU_CAP_EDGE && c5[k].x + c5[k].w <= W - MENU_CAP_EDGE);
        }
        // Выделенной место достаётся целиком — ради её имени в меню и смотрят.
        mcap("выделенной подписи место целиком", c5[2].w, want5[2]);
        // И она стоит по центру экрана, а не подвинутая соседями.
        mcap("выделенная подпись по центру оси", c5[2].x + c5[2].w / 2, W / 2);
        // Соседние не налезают: отрезки идут слева направо с просветом.
        for (int k = 1; k < 5; k++) {
            char what[128];
            snprintf(what, sizeof(what), "подписи %d и %d не налезают", k - 1, k);
            mccap(what, c5[k - 1].x + c5[k - 1].w <= c5[k].x);
        }
        // Каждая — под своей плиткой: середина подписи не дальше полушага от центра
        // плитки. Без этого «не налезают» выполнила бы и раскладка в одну кучу у края.
        for (int k = 0; k < 5; k++) {
            const int mid = c5[k].x + c5[k].w / 2;
            const int tc = (int)(tileCenterF(W, sd5[k]) + 0.5f);
            char what[128];
            snprintf(what, sizeof(what), "подпись %d под своей плиткой", k);
            mccap(what, (mid - tc < STEP1 / 2) && (tc - mid < STEP1 / 2));
        }
        // Кадр проворота: лента стоит между раскладками, нулевого расстояния в ней нет
        // вовсе — и подписи обязаны остаться. Пока сторона считалась по знаку расстояния,
        // здесь пропадали ВСЕ: обе стороны упирались в стену, которую некому отодвинуть.
        const float sdHalf[5] = { -1.5f, -0.5f, 0.5f, 1.5f, 2.5f };
        MenuCap ch[5];
        menuCapLayout(W, sdHalf, want5, 5, 2, ch);   // выделена та, что приехала к центру
        for (int k = 0; k < 4; k++) {                // пятая на полшага уже за краем
            char what[128];
            snprintf(what, sizeof(what), "на провороте подпись %d не пропала", k);
            mccap(what, ch[k].w >= MENU_CAP_MIN);
        }
        // Длинное имя у соседа не крадёт место у выделенной: ей по-прежнему целиком.
        int wantLong[5] = { 60, 300, 60, 60, 60 };
        MenuCap cl[5];
        menuCapLayout(W, sd5, wantLong, 5, 2, cl);
        mcap("длинный сосед не сжал выделенную", cl[2].w, wantLong[2]);
        mccap("длинный сосед обрезан по месту", cl[1].w < wantLong[1]);
        mccap("длинный сосед не налез на выделенную", cl[1].x + cl[1].w <= cl[2].x);
    }
    if (fails == 0) printf("карусель: раскладка сошлась\n");
    return fails == 0 ? 0 : 1;
}
"""


def menu_carousel_test(ctx):
    """Главный экран — карусель плиток в один ряд, а не сетка страниц.

    Старая сетка была по шесть плиток на страницу: вверх-вниз листались страницы, и у
    каждой плитки было только экранное место. Карусель центрирует выделенную плитку,
    листается вбок с заворотом и не знает страниц вовсе. Боковые плитки мельче, чтобы по
    каждую руку влезало по две. Геометрия живёт одной функцией с рисованием — проверяем
    её, а не повторяем числами."""
    draw = ctx.root / "src" / "tdeck_ui_draw.cpp"
    if not draw.is_file():
        ctx.note("     SKIP menu_carousel_test: исходника экрана нет")
        return
    src = draw.read_text(encoding="utf-8")

    # Константы ленты берём из того же файла, что рисует, — проверяем исходник, а не
    # свою копию чисел. Вернись сетка — TILE_S1/STEP1 исчезнут, и это уже падение.
    prelude = """#include <stdint.h>
#include <stdio.h>
"""
    for name in ("TILE", "TILE_S1", "TILE_S2", "STEP1", "STEP2", "MENU_TOP", "MENU_CAP_DY",
                 "MENU_CAP_EDGE", "MENU_CAP_GAP", "MENU_CAP_MIN"):
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
    # Шаг кадра проворота и его длительность: фаза считается в шагах кадра, и без
    # констант проворот ни посчитать, ни проверить. TDECK_ANIM_FRAME_MS лежит в шапке
    # рядом с TDECK_BAR_H, TDECK_SCROLL_MS — в обвязке, которая проворот заводит.
    m = re.search(r"(?m)^#define\s+TDECK_ANIM_FRAME_MS\b(.*)$", mt)
    ctx.check("шаг кадра анимации задан", m is not None,
              "TDECK_ANIM_FRAME_MS не найден — фазу проворота не на чем считать")
    if m is None:
        return
    prelude += "#define TDECK_ANIM_FRAME_MS%s\n" % m.group(1)
    cpp = ctx.root / "src" / "tdeck_ui.cpp"
    ct = cpp.read_text(encoding="utf-8") if cpp.is_file() else ""
    m = re.search(r"(?m)^#define\s+TDECK_SCROLL_MS\b(.*)$", ct)
    ctx.check("длительность проворота задана", m is not None,
              "TDECK_SCROLL_MS не найден — проворота ленты нет?")
    if m is None:
        return
    prelude += "#define TDECK_SCROLL_MS%s\n" % m.group(1)

    # tdeckAppCount на хосте нет — стаб на 8 приложений (3 встроенных + 5 установленных,
    # как в макете). Навигация и попадание от него зависят только через n.
    prelude += "static int tdeckAppCount() { return 8; }\n"

    # Обвязка проворота вырезается одним куском: состояние (curSel), фаза кадра, плавность
    # и старт. Старт считает виртуальный путь через край (−1/n) — короткую дорогу, а не
    # полный круг; без него промежуточный кадр и путь заворота не проверить. millis на
    # хосте нет — стаб, он нужен menuScrollStart.
    try:
        prelude += ctx.span(cpp, "static uint8_t curSel = 0;",
                            "static uint8_t curSel = 0;") + "\n"
        prelude += "static unsigned long millis() { return 0; }\n"
        prelude += ctx.span(cpp, "static bool menuScrollActive = false;",
                            "    menuScrollActive = (next != from);\n}") + "\n"
    except (RuntimeError, ValueError):
        ctx.check("вырезана обвязка проворота", False,
                  "функции нет — проворота ленты нет?")
        return

    # Порядок важен: каждый хелпер зовёт предыдущие, и g++ бы не дал собрать тест, где
    # статика определена позже вызова. Порядок здесь — порядок зависимостей сверху вниз
    # по файлу раскладки.
    # MenuCap — тип, а не функция: объявление берём как есть, иначе menuCapLayout не
    # соберётся. Он объявлен рядом с самой раскладкой подписей.
    prelude += "struct MenuCap { int x; int w; };\n"
    for sig in ("static int tileSizeAt(int d)",
                "static int tileOffsetAt(int d)",
                "static float tileSizeF(float d)",
                "static float tileOffsetF(float d)",
                "static float tileDistF(int i, float selF)",
                "static float tileCenterF(int screenW, float d)",
                "static float tileXf(int screenW, float selF, int i)",
                "static int tileX(int screenW, int sel, int i)",
                "static bool tileVisible(int screenW, int sel, int i)",
                "static int tileY(int screenH)",
                "static int tileTop(int screenH, int size)",
                "int tdeckMenuPages(int screenW, int screenH)",
                "int tdeckMenuPageOf(int screenW, int screenH, int index)",
                "int tdeckMenuHit(int screenW, int screenH, int sel, int x, int y)",
                "int tdeckMenuStep(int screenW, int screenH, int cur, int dcol, int drow)",
                "static void menuCapLayout("):
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


CHAT_NODES_MAIN = r"""
#include <stdio.h>

static int fails = 0;
static void ncap(const char* what, int got, int want) {
    if (got != want) { printf("узлы: %s: получили %d, ждали %d\n", what, got, want); fails++; }
}
static void nccap(const char* what, int got) {
    if (!got) { printf("узлы: %s: ложь\n", what); fails++; }
}

// Ключ узла номер n: первый байт — номер, остальное ноль. Контакт опознаётся ключом,
// больше от ключа в этой проверке ничего не нужно.
static void keyOf(int n, uint8_t* pub) {
    memset(pub, 0, 32);
    pub[0] = (uint8_t)(n + 1);
}

// Слышим узел n: имя по номеру, место — ненулевое, иначе на карту он не попадёт.
static void hear(int n, uint32_t at) {
    uint8_t pub[32];
    keyOf(n, pub);
    char name[16];
    snprintf(name, sizeof(name), "node%d", n);
    g_unix = at;
    tdeckChatOnAdvert(pub, name, 54000000 + n, 37000000 + n);
}

// Есть ли узел n среди тех, что уйдут на карту.
static bool onMap(int n) {
    const int cnt = tdeckChatNodeCount();
    char want[16];
    snprintf(want, sizeof(want), "node%d", n);
    for (int i = 0; i < cnt; i++) {
        int32_t la = 0, lo = 0;
        char nm[24];
        if (!tdeckChatNodeAt(i, &la, &lo, nm, sizeof(nm))) continue;
        if (strcmp(nm, want) == 0) return true;
    }
    return false;
}

int main() {
    // Каналов на узле бывает до восьми (MAX_CHANNELS ядра), и они лежат в том же списке,
    // что услышанные соседи. Заводим их все: именно так список и переполнялся.
    for (int c = 0; c < 8; c++) {
        char nm[16];
        snprintf(nm, sizeof(nm), "#chan%d", c);
        tdeckChatAddChannel(c, nm);
    }
    // Соседей — столько, сколько осталось мест. Их должно быть ровно TDECK_CHAT_MAX - 8,
    // и ни один не должен вытеснить другого: прежде мест оставалось четыре на всю сеть, и
    // на карте узлы «замещали друг друга» — число точек не росло, сколько ни ходи.
    const int ROOM = TDECK_CHAT_MAX - 8;
    // Каналы не должны стоить соседям ни одного места: сколько объявлено под узлы,
    // столько и остаётся сверх восьми каналов.
    ncap("каналы не съели места соседей", ROOM, TDECK_CHAT_NODE_MAX);
    nccap("соседей помещается сотня с лишним", ROOM >= 100);
    for (int n = 0; n < ROOM; n++) hear(n, 1000 + (uint32_t)n);
    ncap("все услышанные на карте", tdeckChatNodeCount(), ROOM);
    for (int n = 0; n < ROOM; n++) {
        char what[128];
        snprintf(what, sizeof(what), "узел %d на карте", n);
        nccap(what, onMap(n));
    }

    // Список полон. Новый сосед вытесняет САМОГО ДАВНЕГО, а не случайного.
    hear(ROOM, 9000);
    ncap("после вытеснения мест столько же", tdeckChatNodeCount(), ROOM);
    nccap("новый узел на карте", onMap(ROOM));
    nccap("ушёл самый давний", !onMap(0));
    nccap("второй по давности остался", onMap(1));

    // Главное: заново услышанный узел перестаёт быть кандидатом на вылет. Прежде срок
    // ставился ОДИН раз, при первом адверте, и живой сосед вылетал из списка, пока
    // говорил в эфире, — а на его место тут же приходил следующий, и так по кругу.
    hear(1, 9100);                       // узел 1 снова в эфире
    hear(ROOM + 1, 9200);                // и приходит ещё один незнакомый
    nccap("заново услышанный остался", onMap(1));
    nccap("вместо него ушёл следующий по давности", !onMap(2));

    // Каналы не вытесняются никогда: они заданы настройками узла, а не услышаны случайно.
    // Проверяем числом бесед: соседей ровно ROOM, остальное — каналы.
    int used = 0, chans = 0;
    for (int i = 0; i < TDECK_CHAT_MAX; i++) {
        if (!chats[i].used) continue;
        used++;
        if (chats[i].isChannel) chans++;
    }
    ncap("каналы на месте", chans, 8);
    // Кольцо помнит хозяина номером: тип этого номера обязан вмещать последнюю беседу.
    // В int8_t номер сто тридцать пятой не влез бы, и кольцо досталось бы не тому.
    nccap("номер беседы помещается в тип хозяина кольца",
          (int)(TDECK_CHAT_MAX - 1) <= (int)((1u << (8 * sizeof(ringOwner[0]) - 1)) - 1));
    ncap("список полон целиком", used, TDECK_CHAT_MAX);

    // Переживание перезагрузки: что сохранили, то и подняли, и порядок вытеснения у
    // поднятых — по времени последнего адверта, а не по порядку записей в файле.
    static TdeckChatContact saved[TDECK_CHAT_MAX];
    const int nsaved = tdeckChatContactsSave(saved, TDECK_CHAT_MAX);
    ncap("сохранили всех соседей", nsaved, ROOM);
    memset(chats, 0, sizeof(chats));
    ringReady = false;
    memset(ringOwner, 0, sizeof(ringOwner));
    chatSeen = 0;
    // Порядок как при настоящем включении: сперва каналы из настроек узла, потом
    // контакты с карты. Без каналов в списке остались бы свободные места, и вытеснение
    // не случилось бы вовсе — проверять было бы нечего.
    for (int c = 0; c < 8; c++) {
        char nm[16];
        snprintf(nm, sizeof(nm), "#chan%d", c);
        tdeckChatAddChannel(c, nm);
    }
    tdeckChatContactsLoad(saved, nsaved);
    ncap("подняли всех соседей", tdeckChatNodeCount(), ROOM);
    // Самый давний из поднятых уходит первым — он и уходит.
    int oldest = -1;
    uint32_t oldestAt = 0xFFFFFFFFu;
    for (int i = 0; i < nsaved; i++)
        if (saved[i].heardUnix < oldestAt) { oldestAt = saved[i].heardUnix; oldest = i; }
    nccap("самый давний найден", oldest >= 0);
    char oldName[24];
    snprintf(oldName, sizeof(oldName), "%s", saved[oldest >= 0 ? oldest : 0].name);
    hear(500, 9999);
    bool stillThere = false;
    for (int i = 0; i < tdeckChatNodeCount(); i++) {
        int32_t la = 0, lo = 0;
        char nm[24];
        if (tdeckChatNodeAt(i, &la, &lo, nm, sizeof(nm)) && strcmp(nm, oldName) == 0)
            stillThere = true;
    }
    nccap("после перезагрузки первым уходит самый давний", !stillThere);

    if (fails == 0) printf("узлы на карте: список сошёлся\n");
    return fails == 0 ? 0 : 1;
}
"""


def chat_nodes_test(ctx):
    """Услышанные узлы помещаются на карту все, и никто не вытесняет живого соседа.

    На плате это выглядело так: на карте четыре точки, и они «замещают друг друга» —
    сколько ни ходи по городу, точек не прибавляется, а те, что были, пропадают. Причин
    было две, и обе в списке бесед (узел с координатами — это контакт переписки, см.
    tdeck_chat.h). Первая: список один на каналы и на соседей, мест в нём было двенадцать,
    а каналов на узле до восьми — соседям оставалось четыре. Вторая: срок, по которому
    выбирают, кого вытеснить, ставился ОДИН раз, при первом адверте, поэтому давно
    знакомый, но вполне живой сосед навсегда оставался первым кандидатом на вылет.

    Проверяем настоящим кодом списка: восемь каналов, полный список соседей, вытеснение
    и перезагрузка."""
    src = ctx.root / "src" / "tdeck_chat.cpp"
    hdr = ctx.root / "include" / "tdeck_chat.h"
    if not (src.is_file() and hdr.is_file()):
        ctx.note("     SKIP chat_nodes_test: переписки рядом нет")
        return
    ht = hdr.read_text(encoding="utf-8")

    prelude = """#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
"""
    for name in ("TDECK_CHAT_CHAN_MAX", "TDECK_CHAT_NODE_MAX", "TDECK_CHAT_MAX",
                 "TDECK_CHAT_MSG_MAX", "TDECK_CHAT_RINGS", "TDECK_CHAT_TEXT_MAX"):
        m = re.search(r"(?m)^#define\s+%s\b(.*)$" % name, ht)
        ctx.check("в переписке задан %s" % name, m is not None,
                  "константа %s не найдена — список бесед проверять не на чем" % name)
        if m is None:
            return
        prelude += "#define %s%s\n" % (name, m.group(1))
    # Часы и millis на хосте свои: адверт ставит heardUnix по time(NULL), а оно и решает,
    # кого вытеснять после перезагрузки.
    prelude += """static unsigned long millis() { return 0; }
static uint32_t g_unix = 1000;
static long time(const void*) { return (long)g_unix; }
"""
    try:
        prelude += ctx.span(hdr, "struct TdeckChatContact {", "};") + "\n"
        prelude += ctx.span(src, "struct ChatMsg {", "};") + "\n"
        prelude += ctx.span(src, "struct Chat {", "};") + "\n"
        prelude += ctx.span(src, "static Chat chats[TDECK_CHAT_MAX];",
                            "static uint32_t chatSeen = 0;") + "\n"
        prelude += """static int chatOpen = -1;
static uint32_t chatGen = 0;
static bool storeDirty = false;
static void storeTouch() { storeDirty = true; }
"""
    except (RuntimeError, ValueError):
        ctx.check("вырезан список бесед", False,
                  "объявлений списка нет — переписка перестроена?")
        return
    for sig in ("static void chatSeenTouch(",
                "static int chatIndexOf(",
                "static ChatMsg* chatRing(",
                "static ChatMsg* chatRingIf(",
                "static Chat* chatFind(",
                "int tdeckChatNodeCount(",
                "bool tdeckChatNodeAt(",
                "int tdeckChatContactsSave(",
                "void tdeckChatContactsLoad(",
                "void tdeckChatAddChannel(",
                "void tdeckChatOnAdvert("):
        try:
            prelude += ctx.grab(src, sig) + "\n"
        except RuntimeError:
            ctx.check("вырезана %s" % sig.rstrip("("), False,
                      "функции нет — список услышанных узлов перестроен?")
            return

    ok, out = ctx.host_run(prelude + CHAT_NODES_MAIN, "chatnodes.cpp", "узлы на карте")
    if ok is None:
        return
    ctx.check("узлы на карте: список сошёлся", ok, out.strip()[:600])


ZOOM_MAIN = r"""
#include <stdio.h>

static int fails = 0;
static void zcap(const char* what, int got, int want) {
    if (got != want) { printf("зум: %s: получили %d, ждали %d\n", what, got, want); fails++; }
}
static void zccap(const char* what, int got) {
    if (!got) { printf("зум: %s: ложь\n", what); fails++; }
}

int main() {
    // Шкала обязана доходить до края. Именно здесь она и врала: квадратиков было
    // «половина уровней с округлением вверх», то есть на один больше, чем шкала умеет
    // заполнить, и на самом близком зуме последний оставался пустым — указатель обещал
    // запас приближения, которого нет.
    zcap("квадратиков ровно половина уровней", ZOOM_CELLS, ZOOM_STEPS / 2);
    {
        int full = -1; bool half = true;
        zoomCells(ZOOM_STEPS - 1, &full, &half);
        zcap("на пределе закрашены все квадратики", full, ZOOM_CELLS);
        zccap("на пределе половинки нет", !half);
    }
    {
        int full = -1; bool half = true;
        zoomCells(0, &full, &half);
        zcap("на дальнем краю не закрашен ни один", full, 0);
        zccap("на дальнем краю половинки нет", !half);
    }
    // Каждый уровень виден отдельно: пара «целых + половинка» своя у каждого. Без этого
    // шкала могла бы выглядеть одинаково на двух разных зумах.
    for (int a = 0; a < ZOOM_STEPS; a++)
        for (int b = a + 1; b < ZOOM_STEPS; b++) {
            int fa = 0, fb = 0; bool ha = false, hb = false;
            zoomCells(a, &fa, &ha);
            zoomCells(b, &fb, &hb);
            if (fa == fb && ha == hb) {
                printf("зум: уровни %d и %d выглядят одинаково\n", a, b);
                fails++;
            }
        }
    // Закрашенного не бывает больше, чем квадратиков.
    for (int l = 0; l < ZOOM_STEPS; l++) {
        int f = 0; bool h = false;
        zoomCells(l, &f, &h);
        if (f > ZOOM_CELLS || (h && f >= ZOOM_CELLS)) {
            printf("зум: уровень %d не влезает в шкалу: целых %d, половинка %d\n", l, f, (int)h);
            fails++;
        }
    }
    // Касание достаёт оба края шкалы и идёт по ней без провалов. По квадратикам уровень
    // не вычислить: их вдвое меньше, и край шкалы касанием не достаётся вовсе.
    zcap("касание у левого края — дальний обзор", zoomLevelAt(ZOOM_X0), 0);
    zcap("касание у правого края — предел", zoomLevelAt(ZOOM_X0 + ZOOM_W), ZOOM_STEPS - 1);
    zcap("касание левее шкалы не уводит ниже нуля", zoomLevelAt(ZOOM_X0 - 20), 0);
    zcap("касание правее шкалы не уводит выше предела",
         zoomLevelAt(ZOOM_X0 + ZOOM_W + 20), ZOOM_STEPS - 1);
    {
        int prev = -1, seen = 0;
        for (int x = ZOOM_X0; x <= ZOOM_X0 + ZOOM_W; x++) {
            const int l = zoomLevelAt(x);
            if (l < prev) { printf("зум: касание пошло вспять на x=%d\n", x); fails++; }
            if (l != prev) { seen++; prev = l; }
        }
        zcap("касанием достаётся каждый уровень", seen, ZOOM_STEPS);
    }
    if (fails == 0) printf("указатель зума: шкала сошлась\n");
    return fails == 0 ? 0 : 1;
}
"""


def map_zoom_scale_test(ctx):
    """Указатель зума на карте — шкала, которая доходит до обоих краёв.

    Пять квадратиков по два уровня: пусто, половинка, один, полтора… пять. Это
    одиннадцать положений, и столько же уровней зума (ZOOM_MIN..ZOOM_MAX). Пока
    квадратиков было «половина уровней с округлением ВВЕРХ», их выходило на один больше,
    чем шкала умеет заполнить: на самом близком зуме последний оставался пустым, и
    указатель обещал запас приближения, которого нет. А касание считалось по квадратикам,
    которых вдвое меньше уровней, — предел шкалы пальцем не достаётся вовсе."""
    src = ctx.root / "apps" / "gps" / "gps.cpp"
    if not src.is_file():
        ctx.note("     SKIP map_zoom_scale_test: приложения карты рядом нет")
        return
    t = src.read_text(encoding="utf-8")
    prelude = """#include <stdint.h>
#include <stdio.h>
"""
    for name in ("MAP_X1", "MAP_Y0", "ZOOM_MIN", "ZOOM_MAX", "ZOOM_STEPS", "ZOOM_CELLS",
                 "ZOOM_CS", "ZOOM_CGAP", "ZOOM_W", "ZOOM_X0"):
        m = re.search(r"(?m)^#define\s+%s\b(.*)$" % name, t)
        ctx.check("в карте задан %s" % name, m is not None,
                  "константа %s не найдена — шкалу зума проверять не на чем" % name)
        if m is None:
            return
        prelude += "#define %s%s\n" % (name, m.group(1))
    for sig in ("static void zoomCells(", "static int zoomLevelAt("):
        try:
            prelude += ctx.grab(src, sig) + "\n"
        except RuntimeError:
            ctx.check("вырезана %s" % sig.rstrip("("), False,
                      "функции нет — шкала зума снова считается внутри рисования?")
            return
    ok, out = ctx.host_run(prelude + ZOOM_MAIN, "zoom.cpp", "указатель зума")
    if ok is None:
        return
    ctx.check("указатель зума: шкала сошлась", ok, out.strip()[:600])

    # Что карта умеет показать, то обязана и предзагружать: иначе обзорный зум
    # открывается в пустоту и ждёт сети.
    dl = ctx.root / "src" / "tdeck_mapdownload.cpp"
    if dl.is_file():
        zmin = re.search(r"(?m)^#define\s+MAPDL_ZMIN\s+(\d+)", dl.read_text(encoding="utf-8"))
        zlo = re.search(r"(?m)^#define\s+ZOOM_MIN\s+(\d+)", t)
        ctx.check("предзагрузка доходит до самого дальнего зума карты",
                  zmin is not None and zlo is not None
                  and int(zmin.group(1)) <= int(zlo.group(1)),
                  "MAPDL_ZMIN выше ZOOM_MIN: обзорные уровни карта показывает, но не "
                  "запасает — они откроются пустыми")


MAPAREA_MAIN = r"""
#include <stdio.h>
#include <string.h>

static int fails = 0;
static void rcap(const char* what, int got, int want) {
    if (got != want) { printf("область: %s: получили %d, ждали %d\n", what, got, want); fails++; }
}

// Что заказали в очередь. Поле 64x64 тайла с запасом — области в проверке меньше.
#define FIELD 64
static bool asked[FIELD][FIELD];
static int  askedN = 0;
static bool present[FIELD][FIELD];

static void reset() {
    memset(asked, 0, sizeof(asked));
    memset(present, 0, sizeof(present));
    askedN = 0;
}

int main() {
    // Прямоугольник 20x20 — это 400 тайлов. Прежний код ставил в очередь 256 и молчал:
    // оба цикла были обрезаны по idx < 256, то есть область больше 16 тайлов по стороне
    // закачивалась частично, и узнать об этом было неоткуда.
    reset();
    tdeckMapDownloadAddRect(15, 10, 10, 29, 29);
    rcap("прямоугольник 20x20 заказан целиком", askedN, 400);
    for (int x = 10; x <= 29; x++)
        for (int y = 10; y <= 29; y++)
            if (!asked[x][y]) { printf("область: тайл %d,%d потерян\n", x, y); fails++; }

    // Углы, заданные наоборот, — та же область.
    reset();
    tdeckMapDownloadAddRect(15, 29, 29, 10, 10);
    rcap("перевёрнутые углы дают ту же область", askedN, 400);

    // Что уже лежит на карте, в очередь не просим.
    reset();
    for (int x = 10; x <= 19; x++) present[x][10] = true;        // целый ряд уже есть
    tdeckMapDownloadAddRect(15, 10, 10, 19, 19);
    rcap("имеющееся не перезаказывается", askedN, 100 - 10);

    // Круг: ровно те тайлы, что внутри радиуса, и ни одного сверх.
    reset();
    const int cx = 30, cy = 30, r = 12;
    tdeckMapDownloadAddCircle(15, cx, cy, r);
    int want = 0;
    for (int dx = -r; dx <= r; dx++)
        for (int dy = -r; dy <= r; dy++)
            if (dx * dx + dy * dy <= r * r) want++;
    rcap("круг радиуса 12 заказан целиком", askedN, want);
    for (int dx = -r; dx <= r; dx++)
        for (int dy = -r; dy <= r; dy++) {
            const bool inside = dx * dx + dy * dy <= r * r;
            if (inside != asked[cx + dx][cy + dy]) {
                printf("область: угол круга %d,%d: внутри=%d заказан=%d\n",
                       dx, dy, (int)inside, (int)asked[cx + dx][cy + dy]);
                fails++;
            }
        }

    // Вырожденные входы: один тайл и нулевой радиус.
    reset();
    tdeckMapDownloadAddRect(15, 5, 5, 5, 5);
    rcap("область в один тайл", askedN, 1);
    reset();
    tdeckMapDownloadAddCircle(15, 5, 5, 0);
    rcap("круг нулевого радиуса — один тайл", askedN, 1);

    if (fails == 0) printf("область карты: заказана целиком\n");
    return fails == 0 ? 0 : 1;
}
"""


def map_area_queue_test(ctx):
    """Область карты уходит в очередь ЦЕЛИКОМ, а не первыми 256 тайлами.

    Было так: кэш на 256 проверок «есть ли тайл» и два одинаковых прохода по области —
    первый наполнял кэш, второй по нему ставил задания. Оба цикла обрезаны по idx < 256,
    поэтому область больше шестнадцати тайлов по стороне уходила в очередь частично. Без
    записи в журнал и без отказа: заказал двести километров — получил уголок, и понять
    это можно было только по тому, что карта не появляется."""
    src = ctx.root / "src" / "tdeck_mapdownload.cpp"
    if not src.is_file():
        ctx.note("     SKIP map_area_queue_test: закачки карты рядом нет")
        return
    prelude = """#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define FIELD 64
extern bool asked[FIELD][FIELD];
extern int  askedN;
extern bool present[FIELD][FIELD];
#define TDECK_DBG(...) do { } while (0)
static bool tdeckMapDownloadTileExists(int, int x, int y) { return present[x][y]; }
static bool tdeckMapDownloadAddTile(int, int x, int y) {
    if (!asked[x][y]) { asked[x][y] = true; askedN++; }
    return true;
}
"""
    for sig in ("static void mapAddArea(",
                "void tdeckMapDownloadAddRect(",
                "void tdeckMapDownloadAddCircle("):
        try:
            prelude += ctx.grab(src, sig) + "\n"
        except RuntimeError:
            ctx.check("вырезана %s" % sig.rstrip("("), False,
                      "функции нет — постановка области в очередь перестроена?")
            return
    # Объявления заказанного идут ПОСЛЕ вырезанных функций: в main они определяются, а
    # extern выше даёт их видеть заглушкам.
    body = MAPAREA_MAIN.replace("static bool asked[FIELD][FIELD];", "bool asked[FIELD][FIELD];")
    body = body.replace("static int  askedN = 0;", "int askedN = 0;")
    body = body.replace("static bool present[FIELD][FIELD];", "bool present[FIELD][FIELD];")
    body = body.replace("#define FIELD 64\n", "")
    ok, out = ctx.host_run(prelude + body, "maparea.cpp", "область карты в очередь")
    if ok is None:
        return
    ctx.check("область карты: заказана целиком", ok, out.strip()[:600])


def png_memory_test(ctx):
    """Декодер PNG берёт крупное из PSRAM и не молчит, когда памяти нет.

    Внутренней памяти на плате 320 КБ, и она же самый дефицитный ресурс. А декодер просит
    много: палитровый тайл 256x256 — это 64 КБ под распакованные строки (h * (stride+1)),
    RGB того же размера — под двести. Остальной крупный код давно кладёт такое в PSRAM;
    декодер был исключением, и отказ у него к тому же молчал — `goto done` без единого
    слова, то есть тайл просто не появлялся, и понять почему было неоткуда."""
    src = ctx.root / "src" / "tdeck_png.cpp"
    if not src.is_file():
        ctx.note("     SKIP png_memory_test: декодера рядом нет")
        return
    t = src.read_text(encoding="utf-8")
    # Смотрим ТЕЛО функции разбора, а не весь файл: мелкие malloc в нём законны.
    try:
        dec = ctx.grab(src, "bool tdeckPngDecode565(")
    except RuntimeError:
        ctx.check("декодер на месте", False, "tdeckPngDecode565 не нашлась")
        return
    code = "\n".join((ln if ln.find("//") < 0 else ln[:ln.find("//")])
                      for ln in dec.splitlines())
    ctx.check("строки и IDAT берутся не из внутренней памяти",
              re.search(r"raw\s*=\s*\(uint8_t\*\)\s*pngBigAlloc", code) is not None
              and re.search(r"idatBuf\s*=\s*\(uint8_t\*\)\s*pngBigAlloc", code) is not None,
              "самые большие буферы декодера снова идут из внутреннего хипа: палитровый "
              "тайл это 64 КБ, RGB — под двести")
    ctx.check("крупное пробует PSRAM прежде внутренней памяти",
              re.search(r"pngBigAlloc[\s\S]{0,400}MALLOC_CAP_SPIRAM", t) is not None,
              "pngBigAlloc не спрашивает PSRAM — тогда он ничем не отличается от malloc")
    ctx.check("размер картинки ограничен",
              "PNG_RAW_MAX" in code,
              "предела на размер нет: порченый заголовок попросит гигабайты, и отказ "
              "придёт позже и глуше")
    ctx.check("нехватка памяти попадает в журнал",
              re.search(r"if\s*\(!d \|\| !raw[\s\S]{0,200}TDECK_DBG", code) is not None,
              "отказ по памяти снова молчит: тайл не появится, а причины в журнале не "
              "будет")


def trackball_step_debounce_test(ctx):
    """Щелчки трекбола за полсекунды — это один шаг, а не несколько.

    Шарик даёт пачку импульсов на каждый щелчок пальца, и без общего окна один щелчок
    листал ленту на несколько плиток. Окно одно на все оси: диагональный толчок — один
    шаг, а не два."""
    inp = ctx.root / "src" / "tdeck_input.cpp"
    if not inp.is_file():
        ctx.note("     SKIP trackball_step_debounce_test: исходника ввода нет")
        return
    src = inp.read_text(encoding="utf-8")
    m = re.search(r"(?m)^#define\s+TRACKBALL_STEP_MS\s+(\d+)", src)
    ctx.check("окно антидребезга трекбола задано", m is not None,
              "TRACKBALL_STEP_MS не найден — щелчки трекбола не схлопываются")
    if m is None:
        return
    ctx.check("окно не меньше полсекунды", int(m.group(1)) >= 500,
              "окно %s мс: пачка щелчков всё ещё размазывается" % m.group(1))
    try:
        code = ctx.grab(inp, "static TdeckEvent pollTrackball()")
    except RuntimeError:
        ctx.check("вырезан pollTrackball", False, "функция не нашлась")
        return
    ctx.check("окно общее для всех осей", "lastStepMs" in code,
              "нет общего времени последнего шага — оси дребезжат независимо")
    ctx.check("внутри окна щелчок гасится",
              "TRACKBALL_STEP_MS" in code and "return TDECK_EV_NONE" in code,
              "нет ветки, которая глошит серию щелчков окном")
    ctx.check("отданный шаг двигает окно", "lastStepMs = millis()" in code,
              "время последнего шага не обновляется — все щелчки после первого потонут "
              "в окне")


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
    # Между условием и вызовом допускается что угодно, кроме точки с запятой: к «часы
    # есть» с тех пор добавилось «и журнал не показывает свою строку», а проверка цвета
    # требовала закрывающей скобки сразу после s.clock[0] и объявляла белые часы мягкими.
    ctx.check("часы рисуются белым",
              re.search(r"s\.clock\[0\][^;]*textAtF\([^;]*COL_WHITE", d) is not None,
              "часы рисуются мягким цветом: на живой панели они сливаются с полосой")
    ctx.check("часы рисуются шрифтом значений",
              re.search(r"s\.clock\[0\][^;]*textAtF\([^;]*FONT_VALUE", d) is not None,
              "часы мельче, чем нужно: на полосе 26 px они теряются среди пиктограмм")


def shadow_frame_test(ctx):
    """Теневая копия кадра: вывод по разнице строк не должен врать о том, что вывел.

    Панель получает только изменившиеся строки — драйвер сравнивает буфер с копией того,
    что уже стоит на экране, и выталкивает различия. Механизм дешёвый (сравнение около
    восьми миллисекунд на кадр против полного вывода в шестьдесят), но у него есть ровно
    одно смертельное свойство: строка, записанная в теневую копию, считается выведенной
    НАВСЕГДА. Поэтому вложенный вызов недопустим — он вытолкнет недорисованный кадр и
    запишет его строки как выведенные, после чего внешний проход их не выведет никогда, и
    на экране останется мешанина из двух кадров до следующей полной перерисовки. Повод для
    вложенного вызова живой: ожидание эфира прошивка вправе занять рисованием (mcAirPump).

    Вторая половина — про честность профиля: время рисования знает только тот, кто рисует.
    Драйвер видит готовый буфер, и когда он передавал за рисование ноль, журнал печатал
    «рисование 0 мс» на кадрах, которые рисовались по сто миллисекунд."""
    drv = ctx.root / "include" / "st7789.h"
    if not drv.is_file():
        ctx.note("     SKIP shadow_frame_test: драйвера панели рядом нет")
        return
    d = drv.read_text(encoding="utf-8")
    try:
        disp = ctx.grab(drv, "void display(void)")
    except RuntimeError:
        ctx.check("вывод кадра на месте", False, "display() не нашлась — драйвер перестроен?")
        return
    code = "\n".join((ln if ln.find("//") < 0 else ln[:ln.find("//")])
                      for ln in disp.splitlines())
    ctx.check("вывод кадра закрыт от повторного входа",
              re.search(r"if\s*\(\s*_inDisplay\s*\)\s*return\s*;", code) is not None,
              "display() пускает вложенный вызов: он вытолкнет недорисованный кадр и "
              "запишет его строки в теневую копию как выведенные")
    # Сторож обязан сниматься на КАЖДОМ выходе после подъёма, иначе первый же ранний
    # возврат выключит вывод кадров навсегда — экран замрёт целиком, и это хуже мешанины.
    # Считаем только то, что ПОСЛЕ подъёма: выходы до него сторожа не трогают.
    raised = code.find("_inDisplay = true")
    tail = code[raised:] if raised >= 0 else ""
    ctx.check("сторож снимается на каждом выходе",
              raised >= 0
              and tail.count("_inDisplay = false") >= tail.count("return;") + 1,
              "у display() есть выход, на котором сторож остаётся поднятым: следующий "
              "кадр не выведется никогда")
    ctx.check("теневая копия обновляется только выведенным",
              "memcpy(_srow(" in code or "memcpy(_shadow" in code,
              "строки больше не переносятся в теневую копию — вывод по разнице сломан")
    # Вывод строк обязан идти ОДНОЙ транзакцией с опущенным CS: окно адреса, команда
    # записи и пиксели неразрывно. Подъём CS между командой и данными для ST7789 — конец
    # потока команды, и на шине, общей с картой и радио, в этот зазор встревает чужой
    # обмен. Строка тогда не ложится на панель, а в теневой копии числится выведенной —
    # и не выводится больше никогда.
    try:
        push = ctx.grab(drv, "void _pushRows(")
    except RuntimeError:
        ctx.check("вывод строк на месте", False, "_pushRows не нашлась — драйвер перестроен?")
        return
    pcode = "\n".join((ln if ln.find("//") < 0 else ln[:ln.find("//")])
                       for ln in push.splitlines())
    ctx.check("вывод строк идёт одной транзакцией",
              pcode.count("SPI.beginTransaction") == 1 and pcode.count("_cs, LOW") == 1,
              "окно адреса и пиксели снова уходят разными транзакциями: CS поднимается "
              "между командой записи и данными, и строка может не лечь на панель")
    ctx.check("внутри вывода не зовутся самостоятельные команды",
              "command(" not in pcode and "spiData(" not in pcode,
              "в _pushRows вернулись command()/spiData() — они берут транзакцию сами и "
              "рвут вывод на части")
    # Полоса сверки: теневая копия — догадка о панели, проверить её нечем, поэтому часть
    # экрана уходит на панель помимо сравнения. Без неё одно расхождение живёт вечно.
    ctx.check("часть экрана уходит помимо сравнения",
              re.search(r"#define\s+ST7789_SCRUB_ROWS\s+[1-9]", d) is not None
              and "_scrubY" in code,
              "полосы сверки нет: разойдись теневая копия с панелью — эти строки не "
              "выведутся больше никогда")
    # Замер вывода кадра пишет на панель мимо теневой копии — и обязан признаться в этом.
    try:
        bench = ctx.grab(drv, "void benchPush(")
        ctx.check("замер кадра требует полного вывода после себя",
                  "_pushAll = true" in bench,
                  "benchPush оставляет панель расходиться с теневой копией: он пишет "
                  "кадры мимо неё, и последние — без перестановки байт")
    except RuntimeError:
        pass          # замера нет — и расходиться нечему
    ctx.check("драйвер не выдумывает время рисования",
              re.search(r"tdeckProfFrame\s*\(\s*0\s*,", d) is None,
              "драйвер снова передаёт за рисование ноль: журнал будет печатать "
              "«рисование 0 мс» на кадрах любой тяжести")
    ui = ctx.root / "src" / "tdeck_ui.cpp"
    if ui.is_file():
        ctx.check("время рисования меряет тот, кто рисует",
                  "tdeckProfFrameDraw(" in ui.read_text(encoding="utf-8"),
                  "никто не сообщает профилю время рисования — в журнале оно будет нулём")


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
