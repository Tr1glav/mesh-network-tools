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
