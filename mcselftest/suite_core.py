"""Проверки ядра протокола (mesh-network-core).

Идут для ЛЮБОЙ цели: ядро одно на все прошивки, и регрессия в нём ломает их все сразу.
Раньше эти проверки лежали в scripts/selftest.py каждого форка — то есть ядро проверялось
из потребителя, и половина проверок была только у meshcore-fork: T-Deck возил то же ядро,
но проверял его на треть.

Каждая функция принимает ctx (mcselftest.harness.Ctx) и берёт из него пути к ядру и к
прошивке, вырезалку функций из исходников и сборку на хосте.

Часть проверок кросс-репозиторные: relay_default_off_test смотрит сразу в оба форка — их и
не получилось бы держать внутри одного из них.
"""
import os
import pathlib
import random
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib

from .cshims import RANDOM_PRELUDE, STRING_PRELUDE


HOST_MAIN = r"""
int main() {
    // buildPingReply: путь приходит из эфира, до 63 хопов по 4 байта
    uint8_t path[63 * 4];
    for (size_t i = 0; i < sizeof(path); i++) path[i] = (uint8_t)i;
    for (int hs = 1; hs <= 4; hs++) {
        for (int hops = 0; hops <= 63; hops++) {
            char out[100];
            memset(out, 'X', sizeof(out));
            buildPingReply(out, sizeof(out), path, hops, hs);
            if (strnlen(out, sizeof(out)) >= sizeof(out)) {
                printf("buildPingReply: строка не завершена hs=%d hops=%d\n", hs, hops);
                return 1;
            }
        }
    }
    // jsonEscape: произвольный текст не должен вылезать за выходной буфер
    for (int len = 0; len < 200; len++) {
        char in[256], out[64];
        for (int i = 0; i < len; i++) in[i] = (char)(1 + rand() % 254);
        in[len] = 0;
        memset(out, 'X', sizeof(out));
        jsonEscape(in, out, sizeof(out));
        if (strnlen(out, sizeof(out)) >= sizeof(out)) {
            printf("jsonEscape: строка не завершена len=%d\n", len);
            return 1;
        }
    }
    // rawBuildFrame: кадр обязан влезать в буфер OTA_RAW_FRAME_MAX и в лимит SX1262
    uint8_t data[OTA_RAW_CHUNK_BYTES + 2], frame[OTA_RAW_FRAME_MAX];
    memset(data, 0xA5, sizeof(data));
    for (int n = 0; n <= (int)sizeof(data); n++) {
        int f = rawBuildFrame(frame, 0x02, 12345, data, n);
        if (f != 9 + n) { printf("rawBuildFrame: длина %d при n=%d\n", f, n); return 1; }
        if (f > 255) { printf("rawBuildFrame: кадр %d > 255 байт\n", f); return 1; }
    }
    // Сюда прошивка дописывает своё: T-Deck проверяет тут же fmtUdeg и nmeaCoord —
    // координаты идут по сети целыми числами, и ошибка в них не падает, а тихо сдвигает
    // точку на карте. Подставляется параметром extra_main, см. host_functions_test.
    %%EXTRA_MAIN%%
    const char* s = "meshcore";
    printf("crc32=%08X\n", (unsigned)~crc32_upd(0xFFFFFFFF, (const uint8_t*)s, strlen(s)));
    printf("crc16=%04X\n", crc16buf((const uint8_t*)s, strlen(s)));
    return 0;
}
"""


def host_functions_test(ctx, extra_funcs=(), extra_main="", extra_label=()):
    """Границы буферов: функции вырезаются из ядра и гоняются на граничных данных.

    extra_funcs — что прошивка хочет проверить в этой же сборке: список пар
    (подсказка пути, начало сигнатуры). extra_main — её кусок C-кода внутрь main().
    extra_label — имена её функций для названия проверки. Так T-Deck добавляет сюда
    fmtUdeg и nmeaCoord, не заводя второй сборки.
    """
    if not shutil.which("g++"):
        ctx.note("SKIP g++ не найден — проверки границ буферов пропущены")
        return
    code = (
        "#include <cstdint>\n#include <cstdio>\n#include <cstring>\n#include <cstdlib>\n"
        "#define OTA_RAW_CHUNK_BYTES 240\n"
        "#define OTA_RAW_FRAME_MAX (11 + OTA_RAW_CHUNK_BYTES)\n"
        "#define RAW_MAGIC0 0xBE\n#define RAW_MAGIC1 0xEF\n"
        + ctx.grab(ctx.core / "src/crypto.cpp", "uint16_t crc16buf(") + "\n"
        + ctx.grab(ctx.core / "src/crypto.cpp", "uint32_t crc32_upd(") + "\n"
        + ctx.grab(ctx.core / "src/crypto.cpp", "void jsonEscape(") + "\n"
        + ctx.grab(ctx.core / "src/mesh_rx.cpp", "void buildPingReply(") + "\n"
        + ctx.grab(ctx.core / "src/ota.cpp", "int rawBuildFrame(") + "\n"
        + "".join(ctx.grab(h, sig) + "\n" for h, sig in extra_funcs)
        + HOST_MAIN.replace("%%EXTRA_MAIN%%", extra_main)
    )
    names = ", ".join(("buildPingReply", "jsonEscape", "rawBuildFrame") + tuple(extra_label))
    ok, out = ctx.host_run(code, "t.cpp", "границы буферов")
    if ok is None:
        return
    ctx.check("границы буферов (%s)" % names, ok, out.strip()[:400])
    got = dict(re.findall(r"(crc\d+)=([0-9A-F]+)", out))
    expect = "%08X" % (zlib.crc32(b"meshcore") & 0xFFFFFFFF)
    ctx.check("crc32 совпадает с zlib", got.get("crc32") == expect,
              "получено %s, ожидалось %s" % (got.get("crc32"), expect))


# ===== Чистые функции: числа и диапазоны настроек =====
# Ошибки живут как раз здесь: диапазон настройки с lo == hi однажды работал наоборот
# документации. Это чистые функции — их можно вырезать из прошивки и прогнать на хосте.
# Прошивка добавляет к набору свои функции параметрами extra_* (см. pure_functions_test).
PURE_PRELUDE = (
    "#include <cstdint>\n#include <cstdio>\n#include <cstring>\n#include <cstdlib>\n"
    "#include <cmath>\n#include <string>\n"
)


PURE_MAIN = r"""
static int fails = 0;
static void expect(bool ok, const char* what) {
    if (!ok) { printf("не сошлось: %s\n", what); fails++; }
}

int main() {
    // --- cfgRangeOk: lo == hi означает «диапазон не задан», а не «ничего нельзя» ---
    expect(cfgRangeOk(12345, 0, 0), "lo==hi пропускает любое значение");
    expect(cfgRangeOk(8, 5, 12), "8 в диапазоне 5..12");
    expect(!cfgRangeOk(4, 5, 12), "4 вне 5..12");
    expect(!cfgRangeOk(13, 5, 12), "13 вне 5..12");
    expect(cfgRangeOk(5, 5, 12) && cfgRangeOk(12, 5, 12), "границы включительно");
    expect(cfgRangeOk(-22, -22, 22), "отрицательная граница");
    // 70000 не должно «пролезть» усечением до uint16 (4464 попало бы в диапазон)
    expect(!cfgRangeOk(70000, 1, 65535), "70000 вне 1..65535");

    // --- fmtFix/parseFixed: печать и разбор чисел без float-printf ---
    const float vals[] = { 0.0f, 1.0f, -1.0f, 62.5f, 868.731018f, -12.25f, 255.0f, 0.05f };
    for (unsigned i = 0; i < sizeof(vals) / sizeof(vals[0]); i++) {
        for (int dec = 0; dec <= 6; dec++) {
            char buf[24];
            memset(buf, 'X', sizeof(buf));
            fmtFix(vals[i], (uint8_t)dec, buf, sizeof(buf));
            if (strnlen(buf, sizeof(buf)) >= sizeof(buf)) {
                printf("fmtFix: строка не завершена v=%f dec=%d\n", (double)vals[i], dec);
                return 1;
            }
            float back = parseFixed(buf);
            float tol = 1.0f;
            for (int k = 0; k < dec; k++) tol /= 10.0f;
            if (fabsf(back - vals[i]) > tol) {
                printf("fmtFix/parseFixed: %f -> %s -> %f (dec=%d)\n",
                       (double)vals[i], buf, (double)back, dec);
                fails++;
            }
        }
    }
    // Тесный буфер: обрезаем, но завершающий ноль обязан остаться
    for (size_t n = 1; n < 12; n++) {
        char small[12];
        memset(small, 'X', sizeof(small));
        fmtFix(-868.731018f, 6, small, n);
        if (strnlen(small, n) >= n) { printf("fmtFix: нет нуля при n=%u\n", (unsigned)n); return 1; }
    }
    expect(parseFixed(" -3,5") < -3.4f && parseFixed(" -3,5") > -3.6f, "parseFixed: запятая и пробел");

    // --- fmtUdeg: микроградусы в строку, включая границы типа ---
    // INT32_MIN — не теоретическая придирка: значение приходит из NMEA и из настроек, то есть
    // извне. Раньше знак снимался через udeg = -udeg, а у знакового отрицания INT32_MIN нет
    // результата в типе: неопределённое поведение, и компилятор вправе выкинуть проверку знака.
    {
        struct { int32_t v; const char* want; } cases[] = {
            { 0,           "0.000000" },
            { 55751244,    "55.751244" },
            { -37617890,   "-37.617890" },
            { 1,           "0.000001" },
            { -1,          "-0.000001" },
            { 2147483647,  "2147.483647" },
            { -2147483647, "-2147.483647" },
            { -2147483648, "-2147.483648" },   // INT32_MIN
        };
        for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            char b[24];
            memset(b, 'X', sizeof(b));
            fmtUdeg(cases[i].v, b, sizeof(b));
            if (strnlen(b, sizeof(b)) >= sizeof(b)) {
                printf("fmtUdeg: строка не завершена при %ld\n", (long)cases[i].v);
                fails++;
            } else if (strcmp(b, cases[i].want) != 0) {
                printf("fmtUdeg: %ld -> %s, ждали %s\n", (long)cases[i].v, b, cases[i].want);
                fails++;
            }
        }
        // Тесный буфер: обрезаем, но ноль остаётся
        for (size_t n = 1; n < 14; n++) {
            char small[14];
            memset(small, 'X', sizeof(small));
            fmtUdeg(-2147483648, small, n);
            if (strnlen(small, n) >= n) {
                printf("fmtUdeg: нет нуля при n=%u\n", (unsigned)n);
                fails++;
            }
        }
    }

    // Сюда прошивка дописывает свои чистые функции: у meshcore-fork это
    // fwVersionCmp и mqttSlug. Подставляется параметром extra_main.
    %%EXTRA_MAIN%%
    if (fails) { printf("проверок не сошлось: %d\n", fails); return 1; }
    printf("ok\n");
    return 0;
}
"""


def pure_functions_test(ctx, extra_funcs=(), extra_main="", extra_prelude="",
                        label="числа и диапазоны настроек"):
    """Чистые функции: числа, диапазоны настроек и то, что прошивка добавит своим списком.

    Ошибки жили как раз здесь: диапазон настройки с lo == hi работал наоборот документации.
    У meshcore-fork к этому набору добавляются fwVersionCmp и mqttSlug (slug из кириллических
    имён когда-то схлопывался в одинаковые подчёркивания), поэтому и название проверки у него
    длиннее — его задаёт параметр label.
    """
    if not shutil.which("g++"):
        ctx.note("SKIP g++ не найден — чистые функции не проверены")
        return
    code = (PURE_PRELUDE + extra_prelude
            + ctx.grab(ctx.core / "src/appconfig.cpp", "bool cfgRangeOk(") + "\n"
            + ctx.grab(ctx.core / "src/crypto.cpp", "char* fmtFix(") + "\n"
            + ctx.grab(ctx.core / "src/crypto.cpp", "float parseFixed(") + "\n"
            + ctx.grab(ctx.core / "src/crypto.cpp", "uint16_t crc16buf(") + "\n"
            + ctx.grab(ctx.core / "src/crypto.cpp", "char* fmtUdeg(") + "\n"
            + "".join(ctx.grab(h, sig) + "\n" for h, sig in extra_funcs)
            + PURE_MAIN.replace("%%EXTRA_MAIN%%", extra_main))
    ok, out = ctx.host_run(code, "p.cpp", label)
    if ok is None:
        return
    ctx.check(label, ok, out.strip()[:600])


MARKER_PRELUDE = (
    "#include <cstdint>\n#include <cstdio>\n#include <cstring>\n"
    "#define BOARD_CODE \"h3\"\n"
    "#define FW_MARK_PREFIX \"MBFW:\"\n"
    "#define min(a,b) ((a)<(b)?(a):(b))\n"
    "struct FwScan { char carry[40]; uint8_t carryLen; bool mine; char other[12]; };\n"
)


MARKER_MAIN = r"""
static void feedAll(FwScan* s, const char* img, size_t n, size_t chunk) {
    fwScanReset(s);
    for (size_t i = 0; i < n; i += chunk) {
        size_t k = (n - i < chunk) ? (n - i) : chunk;
        fwScanFeed(s, (const uint8_t*)img + i, k);
    }
}

int main() {
    char img[4096];
    FwScan s;
    // маркер своей платы обязан находиться при любом размере куска, в том числе
    // когда он лёг на границу двух кусков — это и есть главный риск сканера
    const char* mine = "MBFW:" BOARD_CODE ":1.0.27";
    for (size_t at = 0; at + 64 < sizeof(img); at += 37) {
        memset(img, 0xA5, sizeof(img));
        memcpy(img + at, mine, strlen(mine));
        for (size_t chunk = 1; chunk <= 64; chunk++) {
            feedAll(&s, img, sizeof(img), chunk);
            if (fwScanVerdict(&s) != 1) {
                printf("свой маркер не найден: смещение %zu, кусок %zu\n", at, chunk);
                return 1;
            }
        }
    }
    // образ чужой платы должен быть отвергнут с указанием её кода
    memset(img, 0xA5, sizeof(img));
    memcpy(img + 700, "MBFW:zz9:1.0.27", 15);
    feedAll(&s, img, sizeof(img), 512);
    if (fwScanVerdict(&s) != -1 || strcmp(s.other, "zz9") != 0) {
        printf("чужая плата не распознана: verdict=%d other=%s\n", fwScanVerdict(&s), s.other);
        return 1;
    }
    // без маркера и голый префикс без кода — «неизвестная» прошивка, а не отказ
    memset(img, 0xA5, sizeof(img));
    feedAll(&s, img, sizeof(img), 512);
    if (fwScanVerdict(&s) != 0) { printf("образ без маркера принят за чужой\n"); return 1; }
    memcpy(img + 100, "MBFW:", 6);
    feedAll(&s, img, sizeof(img), 512);
    if (fwScanVerdict(&s) != 0) { printf("голый префикс принят за маркер\n"); return 1; }
    printf("ok\n");
    return 0;
}
"""


def marker_scan_test(ctx):
    if not shutil.which("g++"):
        print("SKIP g++ не найден — сканер маркера платы не проверен")
        return
    code = (MARKER_PRELUDE
            + ctx.grab(ctx.core / "src/ota.cpp", "void fwScanReset(") + "\n"
            + ctx.grab(ctx.core / "src/ota.cpp", "static void fwScanBuf(") + "\n"
            + ctx.grab(ctx.core / "src/ota.cpp", "void fwScanFeed(") + "\n"
            + ctx.grab(ctx.core / "src/ota.cpp", "int fwScanVerdict(") + "\n"
            + MARKER_MAIN)
    with tempfile.TemporaryDirectory() as tmp:
        src = pathlib.Path(tmp) / "m.cpp"
        exe = pathlib.Path(tmp) / "m"
        src.write_text(code, encoding="utf-8")
        build = subprocess.run(
            ["g++", "-std=c++17", "-fsanitize=address,undefined", "-g", str(src), "-o", str(exe)],
            capture_output=True, text=True)
        if build.returncode != 0:
            ctx.check("сборка теста маркера платы", False, build.stderr.strip()[:400])
            return
        run = subprocess.run([str(exe)], capture_output=True, text=True)
        ctx.check("маркер платы: поиск в потоке, в том числе на границах кусков",
              run.returncode == 0, (run.stdout + run.stderr).strip()[:400])


def otaz_test(ctx):
    raw = bytes(random.getrandbits(8) for _ in range(50000))
    packed = (b"OTAZ" + struct.pack("<II", len(raw), zlib.crc32(raw) & 0xFFFFFFFF)
              + zlib.compress(raw, 9))
    size, crc = struct.unpack("<II", packed[4:12])
    # сенсор скармливает распаковщику куски по 240 байт, как они приходят в кадрах
    d = zlib.decompressobj()
    body = packed[12:]
    out = b"".join(d.decompress(body[i:i + 240]) for i in range(0, len(body), 240)) + d.flush()
    ctx.check("формат .otaz: заголовок", packed[:4] == b"OTAZ" and size == len(raw))
    ctx.check("формат .otaz: CRC32 образа", crc == zlib.crc32(raw) & 0xFFFFFFFF)
    ctx.check("формат .otaz: распаковка кусками по 240 Б", out == raw)
    # Бот дописывает в эфир OTA_Z_TAIL_PAD нулей после потока: без них распаковщик узла
    # придерживает хвост образа, и приём падает с «size mismatch». Длину берём из config.h,
    # чтобы проверка и прошивка не разъехались, и убеждаемся, что лишний вход безвреден.
    cfg = (ctx.core / "include/config.h").read_text(encoding="utf-8")
    m = re.search(r"#define\s+OTA_Z_TAIL_PAD\s+(\d+)", cfg)
    ctx.check("формат .otaz: объявлен хвост нулей", m is not None)
    padded = body + bytes(int(m.group(1)) if m else 0)
    dp = zlib.decompressobj()
    outp = b"".join(dp.decompress(padded[i:i + 240]) for i in range(0, len(padded), 240)) + dp.flush()
    ctx.check("формат .otaz: хвостовые нули не портят образ", outp == raw)






FLOOD_GAP_MAIN = r"""
int main() {
    // 1. Пауза обязана попадать в заявленный диапазон: MIN…MAX плюс разброс сверху.
    unsigned int lo = 0xFFFFFFFFu, hi = 0;
    for (unsigned int i = 0; i < 20000; i++) {
        unsigned int g = floodGapMs();
        if (g < lo) lo = g;
        if (g > hi) hi = g;
        if (g < FLOOD_RETRY_MIN_MS || g > FLOOD_RETRY_MAX_MS + FLOOD_JITTER_MS) {
            printf("floodGapMs: %u вне [%d..%d]\n", g, FLOOD_RETRY_MIN_MS,
                   FLOOD_RETRY_MAX_MS + FLOOD_JITTER_MS);
            return 1;
        }
    }
    // 2. Верхняя граница обязана достигаться. Раньше FLOOD_RETRY_MAX_MS был объявлен, но
    //    не использовался: пауза была MIN…MIN+JITTER, и разброс выходил вдвое уже
    //    задуманного, а config.h при этом утверждал, что диапазон шире.
    // random(min, max) в Arduino не включает верхнюю границу, поэтому наибольшая
    // достижимая пауза на единицу меньше заявленной верхней.
    if (hi != FLOOD_RETRY_MAX_MS + FLOOD_JITTER_MS - 1) {
        printf("floodGapMs: максимум %u, а ждали %d — MAX не используется\n",
               hi, FLOOD_RETRY_MAX_MS + FLOOD_JITTER_MS - 1);
        return 1;
    }
    if (lo != FLOOD_RETRY_MIN_MS) {
        printf("floodGapMs: минимум %u, а ждали %d\n", lo, FLOOD_RETRY_MIN_MS);
        return 1;
    }
    // 3. Разброс нужен для того, чтобы копии соседей не совпадали: соседние паузы одного
    //    сообщения обязаны отличаться, иначе флуд снова собирается в залп.
    unsigned int prev = floodGapMs();
    int distinct = 0;
    for (unsigned int i = 0; i < 200; i++) {
        unsigned int g = floodGapMs();
        if (g != prev) distinct++;
        prev = g;
    }
    if (distinct < 150) { printf("floodGapMs: соседние паузы повторяются (%d)\n", distinct); return 1; }
    // 4. Своя база у вызывающего кода: короче минимума — поднимается до него, длиннее
    //    максимума — опускается. Иначе FLOOD_RETRY_MS, заданный кем-то в 20000, тихо
    //    вернул бы кадры в один залп.
    unsigned int clampLo = floodGapMs(1);
    unsigned int clampHi = floodGapMs(60000);
    if (clampLo < FLOOD_RETRY_MIN_MS) { printf("floodGapMs: нижняя граница %u\n", clampLo); return 1; }
    if (clampHi > FLOOD_RETRY_MAX_MS + FLOOD_JITTER_MS) {
        printf("floodGapMs: верхняя граница не удержана: %u\n", clampHi);
        return 1;
    }
    // 5. Нулевая база (вызывающий код не задал паузу) обязана вести себя как FLOOD_RETRY_MS,
    //    а не превращаться в random(0, JITTER) — то есть в паузу короче времени в эфире.
    for (unsigned int i = 0; i < 500; i++) {
        if (floodGapMs(0) < FLOOD_RETRY_MIN_MS) {
            printf("floodGapMs: нулевая база дала %u\n", floodGapMs(0));
            return 1;
        }
    }
    printf("диапазон %u..%u мс\n", lo, hi);
    return 0;
}
"""


def flood_gap_test(ctx):
    """Пауза между копиями флуда.

    Проверяем не «красивые числа», а что пауза действительно разнесена и что верхняя
    граница из config.h используется. Раньше FLOOD_RETRY_MAX_MS был объявлен и не
    использовался: floodSend брал random(MIN, MIN + JITTER), то есть 1000…1500 мс вместо
    заявленных 1000…1800, и разброс между соседями был вдвое уже, чем считалось."""
    if not shutil.which("g++"):
        print("SKIP g++ не найден — пауза между копиями не проверена")
        return
    cfg = (ctx.core / "include" / "config.h").read_text(encoding="utf-8")
    defs = []
    for n in ("FLOOD_RETRY_MIN_MS", "FLOOD_RETRY_MAX_MS", "FLOOD_JITTER_MS"):
        m = re.search(r"^#define\s+" + n + r"\s+(\d+)", cfg, re.M)
        if not m:
            ctx.check("пауза копий: %s определена" % n, False)
            return
        defs.append("#define %s %s" % (n, m.group(1)))
    #     # Значение по умолчанию живёт в заголовке, а не в определении, — без объявления
    # вызов без аргументов (floodGapMs()) не собирается.
    code = (RANDOM_PRELUDE + "\n".join(defs) + "\n"
            + "unsigned int floodGapMs(unsigned int baseMs = 0);\n"
            + ctx.grab(ctx.core / "src/mesh_tx.cpp", "unsigned int floodGapMs(") + "\n"
            + FLOOD_GAP_MAIN)
    exe, build = ctx.host_build(code, "g.cpp")
    if exe is None:
        ctx.check("сборка теста паузы копий", False, build[:400])
        return
    run = subprocess.run([str(exe)], capture_output=True, text=True)
    ctx.check("пауза между копиями разнесена и удержана в границах", run.returncode == 0,
          (run.stdout + run.stderr).strip()[:400])
    if run.returncode == 0:
        print("     " + run.stdout.strip())


# ===== Ретрансляция: решения по кадру =====
# maybeQueueRelay — чистое решение по байтам кадра (всё состояние в статике, время и random
# подменяются), поэтому её можно вырезать и прогнать на хосте. Проверяем ровно то, что
# чинили: полная очередь обязана отдавать NOROOM и НЕ запоминать хэш кадра, иначе все
# следующие копии отправителя считаются дубликатами и кадр теряется целиком.
RELAY_PRELUDE = r"""
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#define FEATURE_RELAY 1
#define RELAY_QUEUE_MAX 8
#define RELAY_DELAY_MIN_MS 1400
#define RELAY_DELAY_MAX_MS 6400
#define RELAY_FLOOD_MAX 32
#define RELAY_FLOOD_MAX_ADVERT 8
#define RELAY_LOOP_OFF      0
#define RELAY_LOOP_MINIMAL  1
#define RELAY_LOOP_MODERATE 2
#define RELAY_LOOP_STRICT   3
#ifndef RELAY_LOOP_DETECT
#define RELAY_LOOP_DETECT RELAY_LOOP_STRICT
#endif
#define RELAY_TX_DELAY_PCT 50
#define RELAY_DELAY_SPREAD 5
#define PAYLOAD_TYPE_REQ      0x00
#define PAYLOAD_TYPE_TXT_MSG  0x02
#define PAYLOAD_TYPE_ACK      0x03
#define PAYLOAD_TYPE_ADVERT   0x04
#define PAYLOAD_TYPE_GRP_TXT  0x05
#define ROUTE_TYPE_FLOOD      0x01
#define RELAY_SEEN_COUNT 24
#define SEEN_HASH_SIZE 8
#define PATH_HASH_SIZE 2
#define RELAY_QUEUED 0
#define RELAY_SKIPPED 1
#define RELAY_NOROOM 2
struct SerialStub {
    int n = 0;
    void printf(const char*, ...) { n++; }
    void print(const char*) {}
    void println() {}
};
static SerialStub Serial;
static bool otaFastMode = false;
static uint8_t bot_pub[32] = {0};
static uint8_t ownShortHash = 0xAB;
static uint32_t relayQueueDrops = 0;
static uint32_t relayForwardedCount = 0;
static unsigned long clockMs = 1000;
static void delay(unsigned long) {}
static unsigned long millis() { return clockMs; }
static unsigned int random(unsigned int howbig) {
    if (howbig == 0) return 0;
    static unsigned long s = 999;
    s = s * 1103515245UL + 12345UL;
    return (unsigned int)((s >> 16) % howbig);
}
long random(long howsmall, long howbig) {
    if (howsmall >= howbig) return howsmall;
    return howsmall + (long)random((unsigned int)(howbig - howsmall));
}
static void txFrame(const uint8_t*, int) {}
// Время кадра в эфире: на хосте радио нет, поэтому считаем ту же формулу, что отдаёт
// RadioLib на плате, для профиля сети (SF8, 62.5 кГц, кодирование 4/7, преамбула 16).
// Заглушка-константа здесь не годится: проверка ниже требует, чтобы задержка переиздания
// РОСЛА вместе с кадром, а с константой она была бы одинаковой для всех размеров.
static uint32_t radioAirtimeMs(int len) {
    if (len <= 0) len = 1;
    if (len > 255) len = 255;
    const int sf = 8, cr = 7, pre = 16;
    const uint32_t symbol_us = ((1000u * 10u) << sf) / 625u;   // BW 62.5 кГц
    int bits = 8 * len + 16 - 4 * sf + 8 + 20;
    if (bits < 0) bits = 0;
    const int sf_divisor = 4 * sf;
    const int n_pre = (bits + sf_divisor - 1) / sf_divisor;
    const uint32_t n_symbol_x4 = (uint32_t)((pre + 8) * 4 + 17 + n_pre * cr * 4);
    const uint32_t us = (symbol_us * n_symbol_x4) / 4;
    return (us + 999) / 1000;
}
static bool meshFrameHashOf(const uint8_t* data, int len, uint8_t out[32]);
// Хэш кадра: mbedtls на хосте нет, а проверять надо решение, а не криптографию.
// Считаем что-то, что зависит ровно от переданных байт, — этого достаточно, чтобы
// отличить «учли путь» от «не учли», и чтобы повтор давал тот же результат.
struct MdCtx { uint32_t acc; };
static void md_starts(MdCtx* c) { c->acc = 2166136261u; }
static void md_update(MdCtx* c, const uint8_t* p, size_t n) {
    for (size_t i = 0; i < n; i++) { c->acc ^= p[i]; c->acc *= 16777619u; }
}
static void md_finish(MdCtx* c, uint8_t out[32]) {
    uint32_t a = c->acc;
    for (int i = 0; i < 32; i++) { a = a * 1664525u + 1013904223u; out[i] = (uint8_t)(a >> 24); }
}
"""


RELAY_MAIN = r"""
static int fails = 0;
static void want(const char* what, int got, int expect) {
    if (got != expect) {
        printf("%s: получено %d, ожидалось %d\n", what, got, expect);
        fails++;
    }
}

// Собирает flood-кадр: заголовок, байт пути, сам путь, тело.
static int mkFrame(uint8_t* f, int hops, uint8_t fill) {
    int at = 0;
    f[at++] = (uint8_t)((0x01 << 2) | 0x01);        // payload_type=1, route=flood
    f[at++] = (uint8_t)(((PATH_HASH_SIZE - 1) << 6) | (hops & 0x3F));
    memset(f + at, fill, hops * PATH_HASH_SIZE);
    at += hops * PATH_HASH_SIZE;
    memset(f + at, fill, 20);   // и тело помечаем: иначе кадры с нулём хопов неразличимы
    return at + 20;
}

int main() {
    uint8_t f[256];
    int n = mkFrame(f, 0, 0x11);
    // Кадр, который никто не трогал, обязан встать в очередь
    want("чистый кадр поставлен в очередь", maybeQueueRelay(f, n), RELAY_QUEUED);
    // Та же копия повторно — дубликат, вторая копия в очередь не идёт
    want("повтор того же кадра пропущен", maybeQueueRelay(f, n), RELAY_SKIPPED);
    // Путь в хэш не входит: копия с достроенным путём обязана матчиться, иначе петля
    uint8_t withPath[256];
    int np = mkFrame(withPath, 1, 0x22);
    // тело должно совпасть с исходным, иначе проверка выше проверяла бы разные кадры
    memcpy(withPath + 4, f + 2, 20);
    want("копия с достроенным путём — дубликат", maybeQueueRelay(withPath, np), RELAY_SKIPPED);

    // Быстрый канал mesh OTA односкачный: ретранслятор там лишний
    otaFastMode = true;
    want("на быстром канале не ретранслируем", maybeQueueRelay(f, n), RELAY_SKIPPED);
    otaFastMode = false;

    // Наш собственный хэш в пути — эхо или петля
    memcpy(bot_pub, "\x11\x22", 2);
    uint8_t loop[256];
    int nl = mkFrame(loop, 1, 0x11);       // первый хоп — наш хэш
    want("свой хэш в пути не ретранслируем", maybeQueueRelay(loop, nl), RELAY_SKIPPED);
    memcpy(bot_pub, "\xEE\xFF", 2);

    // Маршруты с транспортными кодами и direct не переносятся: решает ТИП МАРШРУТА
    uint8_t tr[256];
    int nt = mkFrame(tr, 0, 0x33);
    tr[0] = (uint8_t)((PAYLOAD_TYPE_REQ << 2) | 0x00);   // route = TRANSPORT_FLOOD
    want("флуд с транспортными кодами не ретранслируем", maybeQueueRelay(tr, nt), RELAY_SKIPPED);
    tr[0] = (uint8_t)((PAYLOAD_TYPE_GRP_TXT << 2) | 0x02);   // route = DIRECT
    want("direct-кадр не ретранслируем", maybeQueueRelay(tr, nt), RELAY_SKIPPED);

    // А вот ТИП НАГРУЗКИ переиздание не ограничивает: раньше здесь стояло условие на
    // payload 0x00/0x03 с подписью «транспортные коды», и оно отбрасывало REQ и ACK —
    // то есть подтверждения доставки через нас не проходили. Репитер переносит, а не
    // выбирает: у оригинала allowPacketForward по типу нагрузки не фильтрует вовсе.
    uint8_t ack[256];
    int na = mkFrame(ack, 0, 0x44);
    ack[0] = (uint8_t)((PAYLOAD_TYPE_ACK << 2) | ROUTE_TYPE_FLOOD);
    want("подтверждение доставки переиздаётся", maybeQueueRelay(ack, na), RELAY_QUEUED);
    uint8_t req[256];
    int nq = mkFrame(req, 0, 0x45);
    req[0] = (uint8_t)((PAYLOAD_TYPE_REQ << 2) | ROUTE_TYPE_FLOOD);
    want("запрос переиздаётся", maybeQueueRelay(req, nq), RELAY_QUEUED);

    // Объявления отсечены раньше остальных: advert расходится по всей сети, и каждый
    // лишний хоп множит копии. Предел свой, RELAY_FLOOD_MAX_ADVERT, и он СТРОГО меньше
    // общего — иначе смысла в отдельном числе нет.
    uint8_t adv[256];
    int nadv = mkFrame(adv, RELAY_FLOOD_MAX_ADVERT, 0x55);
    adv[0] = (uint8_t)((PAYLOAD_TYPE_ADVERT << 2) | ROUTE_TYPE_FLOOD);
    want("объявление с исчерпанным пределом пропущено", maybeQueueRelay(adv, nadv),
         RELAY_SKIPPED);
    uint8_t adv2[256];
    int nadv2 = mkFrame(adv2, RELAY_FLOOD_MAX_ADVERT - 1, 0x56);
    adv2[0] = (uint8_t)((PAYLOAD_TYPE_ADVERT << 2) | ROUTE_TYPE_FLOOD);
    want("объявление в пределах лимита переиздаётся", maybeQueueRelay(adv2, nadv2),
         RELAY_QUEUED);
    // Тот же путь, но НЕ объявление — общий предел больше, значит кадр проходит.
    uint8_t txt[256];
    int ntxt = mkFrame(txt, RELAY_FLOOD_MAX_ADVERT, 0x57);
    want("сообщение с тем же путём переиздаётся", maybeQueueRelay(txt, ntxt), RELAY_QUEUED);

    // Битые кадры: путь объявлен длиннее, чем данных в кадре
    uint8_t bad[256];
    memset(bad, 0, sizeof(bad));
    bad[0] = (uint8_t)((0x01 << 2) | 0x01);
    bad[1] = (uint8_t)(((PATH_HASH_SIZE - 1) << 6) | 5);   // 5 хопов, а данных нет
    want("обрезанный кадр пропущен", maybeQueueRelay(bad, 4), RELAY_SKIPPED);
    want("кадр короче заголовка пропущен", maybeQueueRelay(bad, 1), RELAY_SKIPPED);
    // Путь упёрся в общий потолок хопов (RELAY_FLOOD_MAX). Берём ровно потолок: он и есть
    // граница отказа, и шестибитный счётчик хопов до 63 её достигает.
    bad[1] = (uint8_t)(((PATH_HASH_SIZE - 1) << 6) | RELAY_FLOOD_MAX);
    memset(bad + 2, 0x77, RELAY_FLOOD_MAX * PATH_HASH_SIZE);
    want("путь длиннее потолка пропущен",
         maybeQueueRelay(bad, 2 + RELAY_FLOOD_MAX * PATH_HASH_SIZE + 4), RELAY_SKIPPED);
    // На один хоп меньше — проходит: иначе проверка выше ловила бы не потолок, а что угодно.
    uint8_t edge[256];
    memset(edge, 0, sizeof(edge));
    edge[0] = (uint8_t)((PAYLOAD_TYPE_GRP_TXT << 2) | ROUTE_TYPE_FLOOD);
    edge[1] = (uint8_t)(((PATH_HASH_SIZE - 1) << 6) | (RELAY_FLOOD_MAX - 1));
    memset(edge + 2, 0x78, (RELAY_FLOOD_MAX - 1) * PATH_HASH_SIZE);
    memset(edge + 2 + (RELAY_FLOOD_MAX - 1) * PATH_HASH_SIZE, 0x79, 8);
    want("путь на хоп короче потолка проходит",
         maybeQueueRelay(edge, 2 + (RELAY_FLOOD_MAX - 1) * PATH_HASH_SIZE + 8), RELAY_QUEUED);

    // Задержка переиздания обязана РАСТИ вместе с кадром: она выводится из времени кадра в
    // эфире, а не задана одним числом на все размеры. Проверяем не конкретные миллисекунды
    // (там случайность), а то, что верхняя граница у большого кадра выше, чем у малого.
    unsigned long dSmall = 0, dBig = 0;
    for (int i = 0; i < 200; i++) {
        unsigned long a = relayDelayMs(24);
        unsigned long b = relayDelayMs(250);
        if (a > dSmall) dSmall = a;
        if (b > dBig) dBig = b;
    }
    if (!(dBig > dSmall)) {
        printf("задержка переиздания не зависит от размера кадра: %lu против %lu\n",
               dBig, dSmall);
        return 1;
    }
    if (dSmall < RELAY_DELAY_MIN_MS) {
        printf("задержка переиздания ниже нижней границы: %lu\n", dSmall);
        return 1;
    }
    if (dBig > RELAY_DELAY_MAX_MS) {
        printf("задержка переиздания выше объявленного бюджета: %lu > %d\n",
               dBig, RELAY_DELAY_MAX_MS);
        return 1;
    }

    // Главное, что чинили: забитая очередь обязана отпустить следующую копию.
    // Очередь на 8 слотов уже занята кадрами выше? Нет — занимаем её явно.
    // Очередь уже занята кадрами из предыдущих проверок — освобождаем её целиком, иначе
    // «переполнение» наступит раньше, чем мы его устроим.
    clockMs += 100000;
    // Тик отдаёт ОДИН кадр, а не всю очередь (это и починено в meshRelayTick), поэтому
    // освобождать её надо столько раз, сколько в ней слотов. Раньше здесь стоял один вызов:
    // хватало, пока выше в очередь попадал один кадр, и сломалось, как только проверок
    // политики стало больше. Проверка теста на самом тесте — тоже проверка.
    for (int i = 0; i < RELAY_QUEUE_MAX + 2; i++) meshRelayTick();
    uint32_t dropsBefore = relayQueueDrops;
    uint8_t full[9][256];
    int fullLen[9];
    // Первые восемь — в очередь (каждый со своим телом, чтобы хэш различался)
    for (int i = 0; i < RELAY_QUEUE_MAX; i++) {
        fullLen[i] = mkFrame(full[i], 0, (uint8_t)(0x90 + i));
        want("очередь заполняется", maybeQueueRelay(full[i], fullLen[i]), RELAY_QUEUED);
    }
    // Дальше очередь полна: кадр не ставится, но и не запоминается
    uint8_t over[256];
    int nover = mkFrame(over, 0, 0xEE);
    want("переполненная очередь — NOROOM", maybeQueueRelay(over, nover), RELAY_NOROOM);
    if (relayQueueDrops != dropsBefore + 1) {
        printf("счётчик переполнений не вырос: %u -> %lu\n", dropsBefore,
               (unsigned long)relayQueueDrops);
        fails++;
    }
    // Вторая копия того же кадра обязана снова получить шанс, а не «уже виден»
    want("вторая копия при полной очереди — снова NOROOM",
         maybeQueueRelay(over, nover), RELAY_NOROOM);
    // Как только в очереди есть место, кадр проходит
    clockMs += 100000;                       // время ушло, meshRelayTick освободит слоты
    meshRelayTick();
    want("после освобождения очереди кадр проходит", maybeQueueRelay(over, nover), RELAY_QUEUED);

    // ===== Чужая разметка пути =====
    // Размер хэша хопа кадр объявляет сам. Свой путь мы строим константой PATH_HASH_SIZE, и
    // при несовпадении переиздание портит кадр: шаг по чужому пути один, а запись своя.
    // Однобайтовый хэш — это оригинальный MeshCore, встретить его в общем канале штатно.
    clockMs += 100000;
    meshRelayTick();
    for (int hs = 1; hs <= 4; hs++) {
        if (hs == PATH_HASH_SIZE) continue;
        uint8_t alien[256];
        int at = 0;
        alien[at++] = (uint8_t)((0x01 << 2) | 0x01);
        alien[at++] = (uint8_t)(((hs - 1) << 6) | 1);      // один хоп чужого размера
        memset(alien + at, 0x5A + hs, hs);
        at += hs;
        memset(alien + at, 0x5A + hs, 20);
        char what[64];
        snprintf(what, sizeof(what), "хэш хопа %d Б не переиздаём", hs);
        want(what, maybeQueueRelay(alien, at + 20), RELAY_SKIPPED);
    }
    // ...и кадр со своим размером по-прежнему проходит: отказ адресный, а не «всё подряд»
    uint8_t mine[256];
    int nm = mkFrame(mine, 1, 0x6B);
    want("кадр со своим размером хэша проходит", maybeQueueRelay(mine, nm), RELAY_QUEUED);

    // ===== Один кадр за тик =====
    // txFrame ждёт канал до CAD_WAIT_BUDGET_MS (1.5 с) и держит кадр в эфире ещё около
    // полусекунды. Раньше тик отдавал всю очередь одним проходом — полная очередь
    // останавливала главный цикл почти на 16 секунд, и это штатный случай: паузы берутся из
    // одного диапазона, поэтому принятые подряд кадры просрочиваются вместе.
    clockMs += 100000;
    for (int i = 0; i < RELAY_QUEUE_MAX + 2; i++) meshRelayTick();   // очередь начисто
    int queued = 0;
    for (int i = 0; i < RELAY_QUEUE_MAX; i++) {
        uint8_t q[256];
        int nq = mkFrame(q, 0, (uint8_t)(0xC0 + i));
        if (maybeQueueRelay(q, nq) == RELAY_QUEUED) queued++;
    }
    want("очередь набрана целиком", queued, RELAY_QUEUE_MAX);
    clockMs += 100000;                        // просрочены ВСЕ слоты сразу
    uint32_t sentBefore = relayForwardedCount;
    meshRelayTick();
    want("за один тик уходит ровно один кадр",
         (int)(relayForwardedCount - sentBefore), 1);
    meshRelayTick();
    want("следующий тик отдаёт следующий кадр",
         (int)(relayForwardedCount - sentBefore), 2);
    // Очередь обязана разгрузиться целиком — по одному за тик, но без потерь
    for (int i = 0; i < RELAY_QUEUE_MAX; i++) meshRelayTick();
    want("вся очередь разгружается тиками",
         (int)(relayForwardedCount - sentBefore), RELAY_QUEUE_MAX);
    // И пустая очередь ничего не отправляет
    meshRelayTick();
    want("пустая очередь молчит", (int)(relayForwardedCount - sentBefore), RELAY_QUEUE_MAX);

    if (fails) { printf("не сошлось: %d\n", fails); return 1; }
    printf("ok\n");
    return 0;
}
"""


def ota_first_burst_test(ctx):
    """Потерянная первая пачка быстрого режима повторяется, и повтор не вечен.

    Проверяется устройство кода: сессия идёт по радио, на хосте её не прогнать. Но обе
    ошибки видны в исходнике однозначно.

    Ошибка была в том, что ветка повтора стояла под otaChunksSent == 0 — счётчиком
    ОТПРАВЛЕННЫХ кадров, который растёт в otaSendBurst. Первая пачка уходит из otaHandleAck
    ещё до любого таймаута, поэтому к проверке счётчик равен числу кадров пачки, и ветка не
    выполнялась никогда. Условие обязано спрашивать ПОДТВЕРЖДЁННОЕ: окно на нуле и маска
    принятого пуста."""
    src = (ctx.core / "src" / "ota.cpp").read_text(encoding="utf-8")

    # Ветка повтора — та, что зовёт otaSendBurst внутри otaBotTick (в фазе DATA). Ищем её по
    # вызову, а условие берём из ближайшего if сверху: сама ветка короткая и целиком в нём.
    tick = src[src.index("void otaBotTick()"):]
    call = tick.find("otaSendBurst();")
    ctx.check("сторож фазы DATA умеет повторить пачку", call != -1,
              "в otaBotTick нет вызова otaSendBurst — повторять потерянную пачку нечем")
    if call == -1:
        return
    # Ворота ветки — внешний if, а не ближайший сверху: внутри ветки стоит
    # `if (otaRetries > OTA_MAX_RETRIES)`, и поиск «ближайшего if» находил именно его,
    # объявляя верный код неверным. Берём последний if с отступом МЕНЬШЕ, чем у вызова.
    lines = tick[:call].splitlines()
    depth = len(lines[-1]) - len(lines[-1].lstrip())
    gate = next((l for l in reversed(lines)
                 if l.lstrip().startswith("if (") and (len(l) - len(l.lstrip())) < depth), "")

    ctx.check("повтор пачки не зависит от числа ОТПРАВЛЕННЫХ кадров",
              "otaChunksSent" not in gate,
              "ветка снова под otaChunksSent — она не выполнится никогда")
    ctx.check("повтор пачки идёт по неподтверждённому окну", "otaSeq" in gate,
              "условие повтора не смотрит на otaSeq: " + gate.strip())
    ctx.check("повтор пачки смотрит и на маску принятых чанков", "otaWinAcked" in gate,
              "условие не смотрит на otaWinAcked: подтверждённый чанк в нулевом окне "
              "снова считался бы «ничего не дошло»")

    # Вторая половина: повтор обязан стоить ретрая. otaSendBurst не ставит otaPolledMs, а
    # ретраи в otaBotTick копятся только по висящему POLL — без явного счёта ветка крутилась
    # бы вечно, повторяя пачку в мёртвый эфир.
    body = tick[tick.rindex(gate, 0, call):call] if gate else ""
    ctx.check("повтор пачки тратит ретрай", "otaRetries++" in body,
              "ветка повтора не увеличивает otaRetries — цикл без выхода")
    ctx.check("повтор пачки ограничен бюджетом ретраев", "OTA_MAX_RETRIES" in body,
              "ветка повтора не сверяется с OTA_MAX_RETRIES")
    ctx.check("исчерпанный бюджет обрывает сессию", "otaBotAbort" in body,
              "по исчерпании ретраев ветка не зовёт otaBotAbort")

    # Условие означает «ни один чанк не подтверждён В ЭТОЙ СЕССИИ» только если оба поля
    # обнуляются на входе в фазу данных.
    ack = src[src.index("void otaHandleAck()"):]
    ack = ack[:ack.index("\n}")]
    for field in ("otaSeq", "otaWinAcked"):
        ctx.check("%s обнуляется при входе в фазу данных" % field,
                  re.search(r"\b%s\s*=\s*0\s*;" % field, ack) is not None,
                  "otaHandleAck не сбрасывает %s — условие повтора считало бы чужую сессию"
                  % field)


def relay_default_off_test(ctx):
    """Ретранслятором не должен быть никто: FEATURE_RELAY по умолчанию 0.

    Проверяем не поведение, а решение — и именно поэтому проверка нужна. Признак вернуть
    обратно стоит одной цифры, а последствие видно только в эфире: узлы начнут переиздавать
    чужие кадры, и заметит это не сборка, а загруженный канал.

    Три вещи сразу. Значение по умолчанию задаёт ЯДРО (правило поведения сети одно на все
    платы, и второй копии ему не место). Ни один features.h прошивки не задаёт признак сам —
    иначе значение ядра до него не доедет (#ifndef). И ни одно окружение в platformio.ini не
    включает его флагом сборки молча."""
    core_cfg = (ctx.core / "include" / "config.h").read_text(encoding="utf-8")
    m = re.search(r"#ifndef\s+FEATURE_RELAY\s*\n\s*#define\s+FEATURE_RELAY\s+(\d+)", core_cfg)
    ctx.check("ядро задаёт FEATURE_RELAY по умолчанию", m is not None,
          "в config.h ядра нет #ifndef FEATURE_RELAY / #define FEATURE_RELAY")
    if m:
        ctx.check("ретрансляция выключена по умолчанию (FEATURE_RELAY = 0)", m.group(1) == "0",
              "config.h ядра ставит FEATURE_RELAY = " + m.group(1))

    # Прошивки признак не переопределяют: define в их features.h перебил бы значение ядра.
    # Пути берутся от рабочего дерева, а не от проверяемой прошивки: правило одно на обе, и
    # проверять его надо целиком, с какой бы целью нас ни запустили.
    for name, sub in (("форка", "meshcore-fork"), ("tdeck", "tdeck")):
        path = ctx.tree / sub / "lib" / "meshcore" / "include" / "features.h"
        if not path.is_file():
            continue
        txt = path.read_text(encoding="utf-8")
        ctx.check("features.h %s не переопределяет FEATURE_RELAY" % name,
              re.search(r"^\s*#\s*define\s+FEATURE_RELAY\b", txt, re.M) is None,
              "%s задаёт признак сам — значение ядра до него не доедет" % path)

    # ...и ни одно окружение ни одной прошивки не включает его флагом сборки.
    on = []
    for sub in ("meshcore-fork", "tdeck"):
        ini = ctx.tree / sub / "platformio.ini"
        if not ini.is_file():
            continue
        on += ["%s: %s" % (sub, ln.strip()) for ln in ini.read_text(encoding="utf-8").splitlines()
               if re.search(r"-DFEATURE_RELAY\s*=\s*[1-9]", ln)]
    ctx.check("ни одно окружение не включает ретрансляцию", not on,
          "включено в: " + "; ".join(on))

    # Выключенный признак обязан оставлять заглушки: radio_rx и главный цикл зовут обе функции
    # без #if, и без тела ветки !FEATURE_RELAY сборка не слинкуется.
    relay_src = (ctx.core / "src" / "mesh_relay.cpp").read_text(encoding="utf-8")
    stub = re.search(r"#else.*?int\s+maybeQueueRelay\s*\(.*?void\s+meshRelayTick\s*\(",
                     relay_src, re.S)
    ctx.check("при выключенном признаке остаются заглушки обеих функций", stub is not None,
          "в mesh_relay.cpp нет ветки #else с maybeQueueRelay и meshRelayTick")

    # Главный цикл обеих прошивок обязан звать meshRelayTick: иначе включённый признак набивал
    # бы очередь и не разгружал её — признак есть, ретрансляции нет. Ровно так было в tdeck.
    for name, sub in (("форка", "meshcore-fork"), ("tdeck", "tdeck")):
        path = ctx.tree / sub / "lib" / "meshcore" / "src" / "app_main.cpp"
        if not path.is_file():
            continue
        txt = path.read_text(encoding="utf-8")
        ctx.check("главный цикл %s зовёт meshRelayTick" % name,
              re.search(r"^\s*meshRelayTick\s*\(\s*\)\s*;", txt, re.M) is not None,
              "%s не разгружает очередь переизданий" % path)


def build_commits_test(ctx):
    """Каждая сборка коммитит и отправляет, а релиз остаётся за явной просьбой (правило 6).

    Проверяется решение, а не поведение: запускать здесь настоящую сборку с push нельзя, а
    ошибка в этих воротах видна только постфактум — либо код перестал уезжать в репозиторий
    молча, либо, наоборот, CI начал коммитить сам и зациклил себя.

    Пять утверждений на каждую прошивку плюс страховка CI. Ворота живут в
    scripts/copy_firmware.py, в пост-действии сборки: коммитить то, что не собралось, смысла
    нет, поэтому шаг обязан стоять именно там, а не в pre-скрипте."""
    seen = 0
    for name, sub in (("форка", "meshcore-fork"), ("tdeck", "tdeck")):
        cf = ctx.tree / sub / "scripts" / "copy_firmware.py"
        if not cf.is_file():
            continue
        seen += 1
        txt = cf.read_text(encoding="utf-8")

        # Условие, под которым зовётся release.py: ближайший if выше вызова.
        lines = txt.splitlines()
        call = next((i for i, l in enumerate(lines) if "subprocess.run(cmd" in l), None)
        ctx.check("%s: сборка зовёт release.py" % name, call is not None,
                  "в %s нет вызова release.py" % cf)
        if call is None:
            continue
        # Ворота — это внешний if тела функции (отступ 4), а не ближайший сверху: между ним
        # и вызовом стоит `if os.environ.get("RELEASE") == "1"`, и поиск «ближайшего if»
        # находил именно его, объявляя верный код неверным.
        gate = next((lines[i] for i in range(call, -1, -1)
                     if lines[i].startswith("    if ")), "")
        flat = re.sub(r"[\s'\"]", "", gate)

        # Главное: отправка больше НЕ ждёт GIT=1. Правило 6 разрешает коммит без спроса, и
        # ворота, требующие переменную, возвращают прежний запрет чёрным ходом.
        ctx.check("%s: отправка не требует GIT=1" % name,
                  "GIT)==1" not in flat.replace("NOGIT", "_"),
                  "ворота %s снова ждут GIT=1" % cf.name)
        # Но выключить её должно быть можно, и обоими способами: NOGIT=1 нужен CI (иначе push
        # перезапустит workflow), GIT=0 — человеку с незаконченной правкой в дереве.
        ctx.check("%s: NOGIT=1 выключает отправку" % name, "NOGIT)!=1" in flat,
                  "в воротах нет NOGIT")
        ctx.check("%s: GIT=0 выключает отправку" % name,
                  re.search(r"(?<!NO)GIT\)!=0", flat) is not None,
                  "в воротах нет GIT=0")

        # Релиз этими воротами не делается: релизная ветка только при RELEASE=1.
        rel = re.search(r'RELEASE"\)\s*==\s*"1"', txt)
        ctx.check("%s: релизная ветка только при RELEASE=1" % name, rel is not None,
                  "--release добавляется не по RELEASE=1")
        if rel:
            tail = txt[rel.end():rel.end() + 200]
            ctx.check("%s: под RELEASE=1 добавляется именно --release" % name,
                      "--release" in tail, "после проверки RELEASE не добавляется --release")

        # Пост-действие, а не pre: коммитим только то, что собралось.
        ctx.check("%s: ворота стоят в пост-действии сборки" % name,
                  "AddPostAction" in txt, "в %s нет AddPostAction" % cf.name)

        # CI обязан глушить отправку явно. Раньше это была страховка (без GIT=1 и так ничего
        # не уходило), теперь — единственное, что отделяет Actions от бесконечной пересборки.
        wf = ctx.tree / sub / ".github" / "workflows" / "build.yml"
        if wf.is_file():
            ctx.check("%s: CI ставит NOGIT=1 на шаге сборки" % name,
                      re.search(r"NOGIT:\s*'?1'?", wf.read_text(encoding="utf-8")) is not None,
                      "%s не глушит отправку — push из Actions запустит workflow заново" % wf)
    if not seen:
        ctx.note("SKIP build_commits_test: прошивок рядом нет")


def features_defined_test(ctx):
    """Каждый признак, по которому ветвится ЯДРО, определён в features.h каждой прошивки.

    Неопределённое имя в `#if` молча считается нулём. Поэтому ненаписанный `#define` и
    опечатка в имени дают одно и то же — выключенную ветку и полное молчание сборки. Так и
    было: комментарий в начале features.h T-Deck обещает «они всегда определены, но могут
    быть равны нулю», а FEATURE_MQTT, FEATURE_MESH_OTA_SENDER и FEATURE_COMPANION не были
    определены нигде. Поведение совпадало с задуманным по совпадению.

    Напрашивающийся `-Wundef` в build_flags эту работу не делает: он включается на весь
    проект вместе с заголовками ESP-IDF и даёт около двухсот предупреждений на файл
    (CONFIG_IDF_TARGET_ESP32, CONFIG_LOG_COLORS и прочие), в которых наше одно не найти.
    Проверено на сборке T-Deck — флаг снят именно поэтому.

    Исключение одно: FEATURE_RELAY. Его значение по умолчанию задаёт ядро, и `#define` в
    прошивке перебил бы `#ifndef` ядра — за этим следит relay_default_off_test."""
    names = set()
    for d in (ctx.core / "src", ctx.core / "include"):
        for f in sorted(d.rglob("*.cpp")) + sorted(d.rglob("*.h")):
            names |= set(re.findall(r"\bFEATURE_[A-Z0-9_]+", f.read_text(encoding="utf-8")))
    names -= {"FEATURE_RELAY"}
    ctx.check("признаки ядра найдены", len(names) >= 3,
              "в исходниках ядра нашлось всего %d признаков — проверка смотрит не туда"
              % len(names))

    seen = 0
    for name, sub in (("форка", "meshcore-fork"), ("tdeck", "tdeck")):
        path = ctx.tree / sub / "lib" / "meshcore" / "include" / "features.h"
        if not path.is_file():
            continue
        seen += 1
        txt = path.read_text(encoding="utf-8")
        missing = sorted(n for n in names
                         if not re.search(r"^\s*#\s*define\s+%s\b" % n, txt, re.M))
        ctx.check("features.h %s определяет все признаки ядра" % name, not missing,
                  "не определены: " + ", ".join(missing) + " — #if сочтёт их нулём молча")
    if not seen:
        ctx.note("SKIP features_defined_test: прошивок рядом нет")


def loss_counters_live_test(ctx):
    """Каждый счётчик потерь, который показывает страница, может сработать в этой сборке.

    Было так: на странице T-Deck пять счётчиков, из них живой один. `relayQueueDrops` растёт
    только в очереди переизданий (она за FEATURE_RELAY, а он выключен у всех), а
    `replyDropped`, `replyDeferred` и `dmNoPubkey` — только в очереди отложенных ответов,
    которая целиком лежит за `#ifndef SENSOR_NODE`; T-Deck собирается с `SENSOR_NODE=1`.

    Мёртвый счётчик не виден — страницы показывают только ненулевые. Беда в другом: пустая
    строка потерь читается как «потерь нет», то есть страница обещает диагностику, которой у
    неё нет.

    Механизм ответов в сенсоры НЕ переносили: рядом в mesh_rx.cpp стоит обратное решение —
    «сенсорный узел пассивный, пинг и личку не обслуживает». Поэтому вердикт «может ли
    счётчик сработать» задан в ядре (MESH_HAS_* в globals.h), а обе страницы его спрашивают."""
    g = (ctx.core / "include" / "globals.h").read_text(encoding="utf-8")

    # Вердикт живёт в ядре и выведен из того, от чего зависит на самом деле, а не задан числом.
    ctx.check("ядро объявляет MESH_HAS_REPLY_QUEUE", "MESH_HAS_REPLY_QUEUE" in g,
              "вердикта про очередь ответов нет — страницы снова будут решать сами")
    ctx.check("вердикт про ответы выведен из SENSOR_NODE",
              re.search(r"#ifdef\s+SENSOR_NODE\s*\n\s*#\s*define\s+MESH_HAS_REPLY_QUEUE\s+0", g)
              is not None,
              "MESH_HAS_REPLY_QUEUE не выведен из SENSOR_NODE")
    ctx.check("вердикт про ретрансляцию выведен из FEATURE_RELAY",
              re.search(r"#\s*define\s+MESH_HAS_RELAY_QUEUE\s+FEATURE_RELAY", g) is not None,
              "MESH_HAS_RELAY_QUEUE задан не через FEATURE_RELAY — разъедется с признаком")

    # Счётчик и его вердикт: где растёт и чем закрыт на странице.
    guarded = {"relayQueueDrops": "MESH_HAS_RELAY_QUEUE",
               "replyDropped": "MESH_HAS_REPLY_QUEUE",
               "replyDeferred": "MESH_HAS_REPLY_QUEUE",
               "dmNoPubkey": "MESH_HAS_REPLY_QUEUE"}

    # Инкремент каждого счётчика обязан существовать — иначе счётчик мёртв везде, и вердикт
    # ему не поможет.
    src = "\n".join((ctx.core / "src" / f).read_text(encoding="utf-8")
                    for f in ("mesh_rx.cpp", "mesh_relay.cpp", "radio.cpp"))
    for name in list(guarded) + ["cadGiveUps"]:
        ctx.check("счётчик %s где-то растёт" % name, name + "++" in src,
                  "в ядре нет ни одного инкремента %s — счётчик мёртв при любых признаках"
                  % name)

    # Страница T-Deck: каждый счётчик из списка закрыт своим вердиктом.
    page = ctx.tree / "tdeck" / "src" / "tdeck_web.cpp"
    if page.is_file():
        txt = page.read_text(encoding="utf-8")
        block = txt[txt.index("struct { uint32_t v; const char* t; } los[]"):]
        block = block[:block.index("};")]
        for name, macro in guarded.items():
            listed = name in block
            ctx.check("страница T-Deck закрывает %s вердиктом" % name,
                      (not listed) or macro in block,
                      "%s показывается без #if %s — на этой плате он не может сработать"
                      % (name, macro))
    # Страница форка: /info отдаёт мёртвые поля только под вердиктом. Скрипт страницы
    # фильтрует по значению, поэтому отсутствующего поля он просто не покажет.
    web = ctx.tree / "meshcore-fork" / "lib" / "meshcore" / "src" / "web.cpp"
    if web.is_file():
        txt = web.read_text(encoding="utf-8")
        i = txt.find("char loss[")
        ctx.check("/info собирает счётчики потерь отдельным фрагментом", i >= 0,
                  "в web.cpp нет сборки фрагмента потерь — значит все поля уходят всегда, "
                  "включая мёртвые")
        if i >= 0:
            frag = txt[i:txt.index("char json[", i)]
            for field, macro in (("rlq", "MESH_HAS_RELAY_QUEUE"),
                                 ("rdr", "MESH_HAS_REPLY_QUEUE"),
                                 ("rdf", "MESH_HAS_REPLY_QUEUE"),
                                 ("dmn", "MESH_HAS_REPLY_QUEUE")):
                ctx.check("/info отдаёт %s только под вердиктом" % field,
                          field in frag and macro in frag,
                          "поле %s уходит без #if %s" % (field, macro))
            ctx.check("/info всегда отдаёт cadg", "cadg" in frag,
                      "живой счётчик тоже пропал из ответа")


# Копии lib/meshcore, которым РАЗРЕШЕНО расходиться, и почему. Список ведётся руками
# намеренно: расхождение само по себе не ошибка (файлы платформенные), ошибка — расхождение,
# которого никто не заметил. Поэтому новое расхождение обязано попасть сюда осознанно, а
# исчезнувшее — уйти отсюда.
MESHCORE_DIVERGENT = {
    "src/app_main.cpp":       "роли плат и порядок инициализации: у T-Deck экран, SD, клавиатура",
    "src/display.cpp":        "OLED у Heltec против ST7789 у T-Deck",
    "include/app_main.h":     "разный состав хуков платформы",
    "include/board_config.h": "пины и параметры разных плат",
    "include/build_info.h":   "ГЕНЕРИРУЕТСЯ сборкой: версия и хэш исходников",
    "include/cyrillic_glyphs.h": "у T-Deck свои таблицы шрифтов под ST7789",
    "include/display.h":      "разные экраны — разный интерфейс вывода",
    "include/features.h":     "наборы признаков разных плат",
    "include/oled.h":         "OLED против ST7789",
}
# Файлы, которых у T-Deck нет и не должно быть. Список намеренно пуст: обе записи, что в нём
# были (`src/button.cpp` и `include/button.h`), уехали в ядро 5 октября 2026 — логика кнопки
# одинакова на любой плате с кнопкой, а пин и прерывание ушли за хуки. Пустой список не значит
# «проверять нечего»: прочие файлы форка закрыты списком приставок в самой проверке, а запись,
# которой больше нет на диске, ловится проверкой «список файлов форка не врёт».
MESHCORE_FORK_ONLY = {}


def meshcore_copies_test(ctx):
    """Расхождения двух копий lib/meshcore перечислены явно.

    `lib/meshcore` — это не общий слой, а две независимые копии в двух прошивках; в ядро эти
    файлы не поднимаются, потому что платформенные (экран, ввод, роли плат). Расхождение
    поэтому штатно. Не штатно другое: расхождение, про которое никто не знает. Правка в одной
    копии молча не доезжает во вторую, и узнать об этом можно только по поведению платы.

    Поэтому список разрешённых расхождений ведётся руками, а проверка требует, чтобы он
    совпадал с действительностью В ОБЕ СТОРОНЫ: новый разошедшийся файл — провал (расхождение
    не осознано), и файл, записанный как разошедшийся, но ставший одинаковым, — тоже провал
    (список врёт, и следующий читатель поверит ему, а не файлам)."""
    fork = ctx.tree / "meshcore-fork" / "lib" / "meshcore"
    tdeck = ctx.tree / "tdeck" / "lib" / "meshcore"
    if not (fork.is_dir() and tdeck.is_dir()):
        ctx.note("SKIP meshcore_copies_test: рядом нет обеих прошивок")
        return

    same, diff, only_fork, only_tdeck = [], [], [], []
    names = set()
    for sub in ("src", "include"):
        for d in (fork / sub, tdeck / sub):
            if d.is_dir():
                names |= {sub + "/" + f.name for f in d.iterdir() if f.is_file()}
    for rel in sorted(names):
        a, b = fork / rel, tdeck / rel
        if a.is_file() and b.is_file():
            (same if a.read_bytes() == b.read_bytes() else diff).append(rel)
        elif a.is_file():
            only_fork.append(rel)
        else:
            only_tdeck.append(rel)

    unexpected = [r for r in diff if r not in MESHCORE_DIVERGENT]
    ctx.check("новых расхождений копий lib/meshcore нет", not unexpected,
              "расходятся, но в списке не записаны: " + ", ".join(unexpected) +
              " — внесите с причиной в MESHCORE_DIVERGENT или сведите файлы")
    stale = [r for r in MESHCORE_DIVERGENT if r in same]
    ctx.check("список расхождений не содержит лишнего", not stale,
              "записаны как разошедшиеся, а совпадают: " + ", ".join(stale))
    # Файл, которого нет НИ В ОДНОЙ копии, в списке расхождений тоже лишний: так список начал
    # врать после переезда sensor_tasks.cpp в ядро — расхождения нет, а запись о нём осталась.
    gone = [r for r in MESHCORE_DIVERGENT if r not in same and r not in diff
            and r not in only_fork and r not in only_tdeck]
    ctx.check("в списке расхождений нет исчезнувших файлов", not gone,
              "записаны как разошедшиеся, а файлов нет ни у одной прошивки: " + ", ".join(gone))

    # Файл только у форка — тоже решение, а не случайность.
    extra = [r for r in only_fork if r not in MESHCORE_FORK_ONLY
             and not r.startswith(("src/companion", "src/mqtt", "src/web", "src/net",
                                   "src/support", "src/coordinator", "src/fwupdate",
                                   "include/companion", "include/mqtt", "include/web",
                                   "include/net", "include/support", "include/coordinator",
                                   "include/fwupdate", "include/ca_bundle", "include/ota_internal"))]
    ctx.check("файлы, которых нет у T-Deck, перечислены", not extra,
              "есть только у форка и нигде не объяснены: " + ", ".join(extra))
    # И в обратную сторону, как у списка расхождений: запись про файл, которого у форка больше
    # нет, — это ложь, и следующий читатель поверит ей, а не диску. Так список начал врать,
    # когда button.cpp уехал в ядро: записи остались, файлов не стало.
    lying = [r for r in MESHCORE_FORK_ONLY if r not in only_fork]
    ctx.check("список файлов форка не врёт", not lying,
              "записаны как «только у форка», а у форка их нет: " + ", ".join(lying))

    # Кнопки у T-Deck нет — это решение владельца, и копии кода там быть не должно. Теперь
    # цена копии выше, чем была: lib/ прошивки перекрывает библиотеку, то есть вернувшийся
    # button.cpp собирался бы ВМЕСТО ядерного и разошёлся бы с ним молча.
    ctx.check("у T-Deck нет копии кода кнопки",
              not (tdeck / "src" / "button.cpp").exists()
              and not (tdeck / "include" / "button.h").exists(),
              "вернулась копия button.cpp: она перекроет ядро и разойдётся с ним молча")
    feat = (tdeck / "include" / "features.h").read_text(encoding="utf-8")
    # Именно `#if FEATURE_BUTTON` + `#error` подряд. Искать просто «#error» и слово «кнопка»
    # где-нибудь в файле нельзя: других #error в features.h хватает, и проверка проходила бы
    # после удаления нужного — откат это и показал.
    ctx.check("включить кнопку у T-Deck нельзя молча",
              re.search(r"#if\s+FEATURE_BUTTON\s*\n\s*#\s*error", feat) is not None,
              "features.h T-Deck не отказывает на FEATURE_BUTTON=1 — признак включился бы, "
              "и ядро стало бы разбирать кнопку, которой у платы нет: хуки mcButtonAttach/"
              "mcButtonDown здесь закрывать нечем")
    ctx.note("     сводка: копий lib/meshcore две, совпадают %d файлов, расходятся %d, "
             "только у форка %d" % (len(same), len(diff), len(only_fork)))


PEER_PRELUDE = r"""
#include <cstdint>
#include <cstdio>
#include <cstring>
#define PEER_CACHE_MAX 8
struct PeerEntry { bool used; uint8_t hash; uint8_t pub[32]; uint32_t last_seen; };
static PeerEntry peerCache[PEER_CACHE_MAX];
static uint32_t clockMs = 1000;
static unsigned long millis() { return clockMs; }
"""

PEER_MAIN = r"""
int main() {
    int fails = 0;
    // Ключ, начинающийся с 0x00. Раньше слот считали занятым по pub[0] != 0, и такой узел
    // был «неизвестен»: ответ в личку не уходил, dmNoPubkey рос без причины.
    uint8_t zero[32];
    memset(zero, 0xAB, 32);
    zero[0] = 0x00;
    rememberPeerPub(0x5C, zero);
    uint8_t* got = findPeerPub(0x5C);
    if (got == NULL) { printf("ключ с нулевым первым байтом не найден\n"); fails++; }
    else if (memcmp(got, zero, 32) != 0) { printf("найден не тот ключ\n"); fails++; }

    // Неизвестный хэш по-прежнему не находится — иначе «нашлось всё» тоже сошло бы за успех
    if (findPeerPub(0x5D) != NULL) { printf("неизвестный хэш нашёлся\n"); fails++; }

    // Хэш 0x00 в пустом кэше: у свободного слота поле hash тоже нулевое, и без признака
    // занятости он выглядел бы как запись про узел 0x00 с нулевым ключом.
    memset(peerCache, 0, sizeof(peerCache));
    if (findPeerPub(0x00) != NULL) { printf("пустой слот сошёл за узел 0x00\n"); fails++; }
    uint8_t k2[32];
    memset(k2, 0x77, 32);
    rememberPeerPub(0x00, k2);
    uint8_t* g2 = findPeerPub(0x00);
    if (g2 == NULL || memcmp(g2, k2, 32) != 0) { printf("узел 0x00 не запомнился\n"); fails++; }

    // Кэш заполняется без вытеснения, пока есть свободные слоты
    memset(peerCache, 0, sizeof(peerCache));
    for (int i = 0; i < PEER_CACHE_MAX; i++) {
        uint8_t k[32];
        memset(k, (uint8_t)(0x10 + i), 32);
        k[0] = 0x00;                      // все ключи с нулевым первым байтом — худший случай
        clockMs += 10;
        rememberPeerPub((uint8_t)(0x20 + i), k);
    }
    for (int i = 0; i < PEER_CACHE_MAX; i++) {
        if (findPeerPub((uint8_t)(0x20 + i)) == NULL) {
            printf("узел %d вытеснен, хотя место было\n", i);
            fails++;
        }
    }
    // Повторный адверт того же узла обновляет запись, а не занимает второй слот
    uint8_t k3[32];
    memset(k3, 0x99, 32);
    clockMs += 10;
    rememberPeerPub(0x20, k3);
    uint8_t* g3 = findPeerPub(0x20);
    if (g3 == NULL || memcmp(g3, k3, 32) != 0) { printf("повторный адверт не обновил ключ\n"); fails++; }
    int busy = 0;
    for (int i = 0; i < PEER_CACHE_MAX; i++) if (peerCache[i].used) busy++;
    if (busy != PEER_CACHE_MAX) { printf("занято слотов %d\n", busy); fails++; }

    if (fails) { printf("не сошлось: %d\n", fails); return 1; }
    printf("ok\n");
    return 0;
}
"""


def peer_cache_test(ctx):
    """Кэш публичных ключей не теряет узел, чей ключ начинается с нуля.

    Слот считали занятым по `pub[0] != 0`, а первый байт публичного ключа бывает нулём —
    один узел из 256. Для такого узла `findPeerPub` возвращал NULL: ответ в личку не уходил,
    а `dmNoPubkey` рос и показывал «advert не дошёл», хотя адверт дошёл и ключ лежал в кэше.
    Диагностика врала ровно там, где по ней и стали бы разбираться."""
    if not shutil.which("g++"):
        print("SKIP g++ не найден — кэш ключей не проверен")
        return
    code = (PEER_PRELUDE
            + ctx.grab(ctx.core / "src/mesh.cpp", "uint8_t* findPeerPub(") + "\n"
            + ctx.grab(ctx.core / "src/mesh.cpp", "void rememberPeerPub(") + "\n"
            + PEER_MAIN)
    exe, build = ctx.host_build(code, "peer.cpp")
    if exe is None:
        ctx.check("сборка теста кэша ключей", False, build[:500])
        return
    run = subprocess.run([str(exe)], capture_output=True, text=True)
    ctx.check("кэш ключей: нулевой первый байт, узел 0x00, заполнение без вытеснения",
              run.returncode == 0, (run.stdout + run.stderr).strip()[:600])

    # Признак занятости обязан быть в самой структуре: без него проверка выше собралась бы
    # со своим объявлением PeerEntry и молчала о том, что в ядре поля нет.
    cfg = (ctx.core / "include" / "config.h").read_text(encoding="utf-8")
    ctx.check("PeerEntry несёт признак занятости",
              re.search(r"struct\s+PeerEntry\s*\{[^}]*\bbool\s+used\s*;", cfg, re.S) is not None,
              "в PeerEntry нет поля used — занятость слота снова определяется по ключу")


def group_text_bound_test(ctx):
    """Расшифровка группового текста сама ограничивает длину, а не верит вызывающему.

    `decryptGroupText` пишет в буфер фиксированного размера ровно `len` байт, а `len` приходит
    параметром. Сегодня единственный вызывающий — разбор кадра, и больше 240 там не бывает: кадр
    в эфире короче. Но это свойство вызывающего, а не функции; появится второй (по сети, из
    приложения, из тестов) — и переполнение стека станет тихим.

    На хосте функцию не прогнать: она тянет mbedtls. Проверяется устройство — предел есть, он
    назван константой, тем же именем объявлен буфер, и стоит он ДО расшифровки."""
    src = (ctx.core / "src" / "crypto.cpp").read_text(encoding="utf-8")
    fn = ctx.grab(ctx.core / "src/crypto.cpp", "String decryptGroupText(")

    m = re.search(r"uint8_t\s+plaintext\[([A-Za-z_][A-Za-z_0-9]*)\]", fn)
    ctx.check("буфер расшифровки объявлен через именованный предел", m is not None,
              "plaintext объявлен числом: предел и буфер разъедутся при первой же правке")
    if not m:
        return
    name = m.group(1)
    ctx.check("предел задан макросом в том же файле",
              re.search(r"#\s*define\s+%s\s+\d+" % re.escape(name), src) is not None,
              "%s нигде не определён числом" % name)

    guard = re.search(r"if\s*\(\s*len\s*>\s*%s\s*\)\s*return" % re.escape(name), fn)
    ctx.check("длина сверяется с этим же пределом", guard is not None,
              "в decryptGroupText нет отказа по len > %s — предел держится на вызывающем" % name)
    if guard:
        loop = fn.find("mbedtls_aes_crypt_ecb")
        ctx.check("предел проверяется ДО расшифровки", guard.start() < loop,
                  "отказ по длине стоит после цикла расшифровки — переполнение уже случилось")


def cfg_reply_queue_test(ctx):
    """Ответ узла на «cfg get» уходит очередью, а не блокирующими паузами.

    Было: между частями ответа стоял `delay(1500)` прямо в разборе команды. Частей бывает три,
    то есть узел на три секунды перестаёт обслуживать радио, сторожа сессий прошивки и свои
    задачи — и делает это по чужой команде из эфира. Вторая ошибка в том же месте: предел длины
    части проверялся ДО добавления поля, поэтому одно длинное поле всё равно уезжало частью
    длиннее предела.

    Проверяется устройство: сессия и эфир на хосте недоступны, но каждое из утверждений видно
    в исходнике однозначно."""
    src = (ctx.core / "src" / "appconfig.cpp").read_text(encoding="utf-8")
    hdr = (ctx.core / "include" / "appconfig.h").read_text(encoding="utf-8")
    cfg = (ctx.core / "include" / "config.h").read_text(encoding="utf-8")
    get = src[src.index('if (rest == "get")'):]
    get = get[:get.index("\n    }")]
    # Комментарии выкидываем: в этой ветке стоит объяснение «раньше здесь был delay(1500)», и
    # поиск по тексту находил именно его — проверка объявляла верный код неверным.
    code = "\n".join((ln if ln.find("//") < 0 else ln[:ln.find("//")]) for ln in get.splitlines())

    # 1. Никаких блокирующих пауз в разборе команды.
    ctx.check("в ответе на «cfg get» нет delay()", "delay(" not in code,
              "в ветке ответа снова стоит delay — узел глохнет на время ответа")
    ctx.check("части ответа кладутся в очередь", "cfgReplyPush(" in code,
              "части не уходят в очередь — значит отправляются прямо из разбора команды")
    ctx.check("разбор команды сам ничего не отправляет", "sensorSendMsg(" not in code,
              "ветка ответа отправляет сама: очередь есть, но её обходят")

    # 2. Предел и очередь заданы в ядре числами, а не прошивкой и не на месте.
    for name in ("CFG_GET_PART_MAX", "CFG_REPLY_QUEUE_MAX", "CFG_REPLY_GAP_MS"):
        ctx.check("%s задан в config.h ядра" % name,
                  re.search(r"#\s*define\s+%s\s+\d+" % name, cfg) is not None,
                  "%s не найден числом в config.h: правило поведения сети одно на все платы"
                  % name)
    ctx.check("предел части взят из константы", "CFG_GET_PART_MAX" in code,
              "в ветке ответа предел задан числом на месте")

    # 3. Предел проверяется ПОСЛЕ добавления поля, и одно длинное поле обрезается.
    ctx.check("длинное поле обрезается до размера части",
              "piece.substring(" in code,
              "одно поле длиннее части уйдёт как есть — часть вылезет за предел")
    ctx.check("пустая часть в очередь не кладётся", "out.length() > strlen(" in code,
              "последняя часть отправляется без проверки, что в ней есть поля")

    # 4. Тик обязан быть объявлен и вызван в ЗАДАЧАХ УЗЛА каждой прошивки. Очередь без вызова —
    # это ответ, который никогда не уйдёт; ровно так было с meshRelayTick в tdeck.
    ctx.check("cfgReplyTick объявлен в заголовке ядра", "void cfgReplyTick();" in hdr,
              "без объявления прошивка не сможет его позвать")
    ctx.check("cfgReplyTick ждёт тишины в эфире", "otaAnySessionActive()" in
              src[src.index("void cfgReplyTick()"):src.index("void cfgReplyTick()") + 700],
              "очередь ответа выходит в эфир во время прошивки по радио")
    # Расписание задач узла с 1 октября 2026 живёт в ядре (sensor_tasks_in_core_test), и
    # разгружать очередь обязано оно. Раньше здесь перебирались копии
    # `<прошивка>/lib/meshcore/src/sensor_tasks.cpp`: после переезда их не стало, обе ветви
    # цикла уходили в `continue`, и проверка молча печатала «прошивок рядом нет» — при том
    # что прошивки лежали рядом. Это ровно тот тихий пропуск, ради которого заведён
    # wiring_test, только внутри одной проверки.
    path = ctx.core / "src" / "sensor_tasks.cpp"
    ctx.check("задачи узла зовут cfgReplyTick",
              path.is_file() and re.search(r"^\s*cfgReplyTick\s*\(\s*\)\s*;",
                                           path.read_text(encoding="utf-8"), re.M) is not None,
              "%s не разгружает очередь ответа — ответ на «cfg get» не уйдёт никогда" % path)


def provision_console_budget_test(ctx):
    """Скрипт настройки ждёт ответ платы дольше, чем плата может молчать.

    Главный цикл прошивки на время передачи стоит ЦЕЛИКОМ: `radio.transmit()` блокирующий, а
    `floodSend` между копиями берёт `delay()`. Пока цикл стоит, `cfgConsoleTick()` не читает
    порт, и ответа на `set` не будет — не потому что плата отказала, а потому что команду ещё
    не прочитали.

    В `provision.py` стоял таймаут 4 с при худшем случае около 10.6 с, и запись падала ровно
    тогда, когда узел что-то передавал: в ответе на `set wifi_ssid` приходило `[TX] OK`.
    Выглядело это как отказ устройства.

    Проверка считает худший случай САМА, из `config.h` ядра, и требует, чтобы число в скрипте
    его покрывало. Сверять с константой нельзя: вырастет число копий флуда или пауза между
    ними — и прежний таймаут снова окажется коротким, а проверка этого не заметит."""
    def val(txt, name):
        m = re.search(r"(?m)^#define\s+%s\s+(\d+)" % name, txt)
        return int(m.group(1)) if m else None

    cfg = (ctx.core / "include" / "config.h").read_text(encoding="utf-8")
    nums = {n: val(cfg, n) for n in ("FLOOD_REPEATS", "CAD_WAIT_BUDGET_MS", "FRAME_AIRTIME_MS",
                                     "FLOOD_RETRY_MAX_MS", "FLOOD_JITTER_MS")}
    missing = [n for n, v in nums.items() if v is None]
    ctx.check("бюджеты флуда заданы числами в config.h", not missing,
              "не нашлось в config.h: " + ", ".join(missing) +
              " — худший случай занятости цикла не вычислить")
    if missing:
        return
    worst_ms = (nums["FLOOD_REPEATS"] * (nums["CAD_WAIT_BUDGET_MS"] + nums["FRAME_AIRTIME_MS"])
                + (nums["FLOOD_REPEATS"] - 1) * (nums["FLOOD_RETRY_MAX_MS"]
                                                 + nums["FLOOD_JITTER_MS"]))
    seen = 0
    for name, sub in (("форка", "meshcore-fork"), ("tdeck", "tdeck")):
        pv = ctx.tree / sub / "scripts" / "provision.py"
        if not pv.is_file():
            continue
        seen += 1
        txt = pv.read_text(encoding="utf-8")

        # Таймаут по умолчанию не задан числом: иначе он не поедет за бюджетами ядра.
        ctx.check("talk() %s берёт таймаут не числом" % name,
                  re.search(r"def talk\([^)]*timeout=None", txt) is not None,
                  "в подписи talk() стоит число: оно не поднимется вместе с бюджетами флуда")
        ctx.check("таймаут %s выводится из config.h ядра" % name,
                  "def console_reply_timeout" in txt
                  and all(n in txt for n in ("FLOOD_REPEATS", "CAD_WAIT_BUDGET_MS",
                                             "FRAME_AIRTIME_MS", "FLOOD_RETRY_MAX_MS",
                                             "FLOOD_JITTER_MS")),
                  "скрипт не считает худший случай по бюджетам ядра")

        # Главное: ЗАПУСКАЕМ функцию скрипта и сверяем её число с худшим случаем. Разбирать
        # текст формулы бессмысленно — проверять надо результат.
        fn = re.search(r"(?ms)^def console_reply_timeout\(.*?(?=^\S)", txt)
        ctx.check("функция таймаута %s вырезается целиком" % name, fn is not None,
                  "не нашлась def console_reply_timeout — проверить результат нечем")
        if fn:
            ns = {"re": re, "pathlib": pathlib, "ROOT": ctx.tree / sub}
            try:
                exec(fn.group(0), ns)
                got = ns["console_reply_timeout"](core_dir=ctx.core)
            except Exception as e:                       # noqa: BLE001 — любая поломка важна
                got = None
                ctx.note("     таймаут %s не посчитался: %s" % (name, e))
            ctx.check("таймаут %s покрывает худший случай (%.1f с)" % (name, worst_ms / 1000.0),
                      got is not None and got * 1000.0 >= worst_ms,
                      "скрипт ждёт %s с, а цикл может молчать %.1f с — занятость платы "
                      "станет «устройство не подтвердило»"
                      % (got, worst_ms / 1000.0))
            # И без ядра рядом он обязан остаться разумным: скрипт запускают из релиза.
            try:
                bare = ns["console_reply_timeout"](core_dir="/nonexistent")
            except Exception:                            # noqa: BLE001
                bare = None
            ctx.check("без ядра рядом таймаут %s не обнуляется" % name,
                      bare is not None and bare >= 10.0,
                      "резервное значение %s с: скрипт из распакованного релиза снова "
                      "упрётся в занятость платы" % bare)

        # Повтор команды: один флуд — не предел, передачи идут подряд.
        ctx.check("у %s команда повторяется после молчания" % name,
                  re.search(r"if not ok and not refused\(buf\)", txt) is not None,
                  "молчание платы сразу считается отказом, хотя set/clear идемпотентны")
        # На ЯВНЫЙ отказ повтора быть не должно: ответ не изменится, а ошибка спрячется.
        ctx.check("у %s явный отказ не повторяется" % name,
                  "def refused(" in txt and "REFUSALS" in txt,
                  "нет разделения «молчит» и «отказала»: повтор спрячет неверное значение")
        # Молчание не значит «не дошло»: плата могла ответить позже таймаута, и тогда поле
        # применено в ОЗУ, а в NVS не записано. Узел остаётся с половиной новых настроек, и
        # заметить это нельзя — "show" покажет ОЗУ. Сброс возвращает сохранённое состояние.
        tail = txt[txt.find("ОШИБКА — устройство не подтвердило"):][:1200]
        ctx.check("%s сбрасывает плату после неподтверждённой записи" % name,
                  'b"reboot' in tail,
                  "скрипт уходит, оставив плату с применённым в ОЗУ и несохранённым в NVS")
    if not seen:
        ctx.note("SKIP provision_console_budget_test: прошивок рядом нет")



def lora_airtime_ms(length, sf, bw_khz, cr, preamble, crc=True, ldro=False):
    """Сколько миллисекунд кадр такой длины занимает эфир. Та же формула, что в радио.

    Считается по разделу 6.1.4 даташита SX1268 — ровно так, как это делает
    SX126x::calculateTimeOnAir() в RadioLib, целочисленно и теми же коэффициентами. Это важно:
    проверка сверяет константу прошивки с тем, что получится на плате, и своя «похожая»
    формула сверяла бы её с чем-то третьим.

    cr — знаменатель кодирования в записи RadioLib (5..8 означает 4/5..4/8).
    """
    symbol_us = ((1000 * 10) << sf) // int(bw_khz * 10)
    sf_coeff1_x4, sf_coeff2 = (25, 0) if sf in (5, 6) else (17, 8)
    sf_divisor = 4 * (sf - 2) if ldro else 4 * sf
    bits = 8 * length + (16 if crc else 0) - 4 * sf + sf_coeff2 + 20
    if bits < 0:
        bits = 0
    n_pre_coded = (bits + sf_divisor - 1) // sf_divisor
    n_symbol_x4 = (preamble + 8) * 4 + sf_coeff1_x4 + n_pre_coded * cr * 4
    return (symbol_us * n_symbol_x4) // 4 // 1000


def radio_profile(ctx, sub):
    """Профиль радио по умолчанию из board_config.h прошивки: (sf, bw, cr, преамбула).

    Профиль живёт в прошивке, а не в ядре: частота и полоса — свойство платы и региона. Для
    бюджетов ядра берётся именно он, потому что на этапе сборки другого знания нет; что
    настройки могут разойтись с профилем в NVS, ловит уже прошивка при старте радио.
    """
    bc = ctx.tree / sub / "lib" / "meshcore" / "include" / "board_config.h"
    if not bc.is_file():
        return None
    txt = bc.read_text(encoding="utf-8")

    def val(name, cast):
        m = re.search(r"(?m)^\s*#\s*define\s+%s\s+([0-9.]+)" % name, txt)
        return cast(m.group(1)) if m else None

    sf, bw, cr, pre = (val("LORA_SF", int), val("LORA_BW", float),
                       val("LORA_CR", int), val("LORA_PREAMBLE", int))
    if None in (sf, bw, cr, pre):
        return None
    return sf, bw, cr, pre


def airtime_budget_test(ctx):
    """FRAME_AIRTIME_MS — это настоящее время самого большого кадра в эфире, а не круглое число.

    Здесь была одна из самых дорогих ошибок в дереве: константа называлась «грубой верхней
    оценкой для SF8/BW62.5» и равнялась 500 мс, но её никто не считал. По формуле даташита на
    этом профиле кадр 255 Б висит в эфире 1979 мс — вчетверо больше. А из этой константы
    выведены ВСЕ бюджеты ожидания: TX_WORST_MS, RELAY_WORST_MS, PING_TIMEOUT_MS,
    PING_MODE_CYCLE_MS, OTA_SLOW_RESP_MS, OTA_SLOW_AIR_BUSY_MS. То есть ответ, пришедший
    вовремя по меркам эфира, засчитывался потерей — и тем вернее, чем длиннее сообщение.

    Проверка считает время кадра сама, по профилю радио из board_config.h прошивки, и требует
    двустороннего совпадения: константа обязана покрывать самый большой кадр (иначе бюджеты
    коротки) и не должна быть завышена вдвое (иначе это не граница, а запас на всякий случай,
    и сеть ждёт впустую)."""
    cfg = (ctx.core / "include" / "config.h").read_text(encoding="utf-8")

    def const(name):
        m = re.search(r"(?m)^#define\s+%s\s+(\d+)\b" % name, cfg)
        return int(m.group(1)) if m else None

    budget = const("FRAME_AIRTIME_MS")
    ctx.check("FRAME_AIRTIME_MS задан числом", budget is not None,
              "константа не найдена — бюджеты не на чём проверять")
    if budget is None:
        return

    seen = 0
    for name, sub in (("форка", "meshcore-fork"), ("tdeck", "tdeck")):
        prof = radio_profile(ctx, sub)
        if prof is None:
            continue
        seen += 1
        sf, bw, cr, pre = prof
        worst = lora_airtime_ms(255, sf, bw, cr, pre)
        ctx.check("бюджет кадра покрывает профиль %s (SF%d/%g кГц/4-%d)" % (name, sf, bw, cr),
                  budget >= worst,
                  "кадр 255 Б висит в эфире %d мс, а FRAME_AIRTIME_MS = %d: все выведенные "
                  "отсюда таймауты короче нужного" % (worst, budget))
        ctx.check("бюджет кадра не завышен у %s" % name, budget <= worst * 2,
                  "FRAME_AIRTIME_MS = %d при настоящих %d мс: это не граница, а запас, и "
                  "сеть ждёт вдвое дольше нужного" % (budget, worst))
        # Пауза между копиями берётся из времени ЭТОГО кадра (floodSend), но зажимается в
        # [FLOOD_RETRY_MIN_MS, FLOOD_RETRY_MAX_MS]. Потолок обязан быть не ниже времени
        # самого большого кадра, иначе зажим опустит его паузу ниже его же эфира — и
        # следующая копия ляжет на предыдущую.
        gap_max = const("FLOOD_RETRY_MAX_MS")
        ctx.check("потолок паузы флуда не режет самый большой кадр (%s)" % name,
                  gap_max is not None and gap_max >= worst,
                  "FLOOD_RETRY_MAX_MS = %s, а кадр 255 Б висит %d мс" % (gap_max, worst))
        ctx.note("     %s: кадр 16 Б — %d мс, 64 Б — %d мс, 240 Б — %d мс, 255 Б — %d мс"
                 % (name, lora_airtime_ms(16, sf, bw, cr, pre),
                    lora_airtime_ms(64, sf, bw, cr, pre),
                    lora_airtime_ms(240, sf, bw, cr, pre), worst))

    # База паузы обязана браться из кадра, а не из константы: иначе короткие сообщения
    # (heartbeat, пинги, команды — почти весь обмен) ждут столько же, сколько самое большое.
    tx = (ctx.core / "src" / "mesh_tx.cpp").read_text(encoding="utf-8")
    ctx.check("пауза флуда выводится из времени этого кадра",
              re.search(r"gapBaseMs\s*=\s*radioAirtimeMs\s*\(\s*f\s*\)", tx) is not None,
              "floodSend не спрашивает radioAirtimeMs(f): пауза снова одна на все размеры")
    rad = (ctx.core / "src" / "radio.cpp").read_text(encoding="utf-8")
    ctx.check("время кадра берётся у радио, а не вычисляется заново",
              "getTimeOnAir" in rad,
              "radioAirtimeMs не спрашивает радио: своя копия формулы разойдётся с модулем")
    # И отклонение настроек от профиля обязано быть ЗАМЕТНО: настройки лежат в NVS.
    # И не в Serial, а в slog: у сенсора, прошивальщика и компаньона USB не подключён
    # никогда, а настройки радио меняются по сети. Предупреждение, видное только по кабелю,
    # для узла в поле не существует — и это обнаружилось сразу, на первой же проверке по
    # сети: прошивка стояла на четырёх платах, а подтвердить расчёт было нечем.
    ctx.check("прошивка ругается, если настройки вышли за бюджет",
              "FRAME_AIRTIME_MS" in rad and "ВНИМАНИЕ" in rad,
              "initLoRa не сверяет настоящее время кадра с бюджетом: узел на SF11 молча "
              "получит короткие пороги")
    ctx.check("сверка бюджета видна без USB",
              re.search(r"#if\s+FEATURE_MESH_OTA_SENDER\s*\n\s*slog\(", rad)
              is not None,
              "строка про время кадра идёт только в Serial: на узле в поле её не прочитать, "
              "а настройки радио меняются со страницы координатора")
    if not seen:
        ctx.note("SKIP airtime_budget_test: профиля радио рядом нет")


def secrets_example_test(ctx):
    """Пример настроек развёртывания подходит СВОЕЙ прошивке.

    Оба примера были побайтовой копией друг друга: в `tdeck/secrets.example.json` лежали MQTT,
    `coord_ip` и четыре устройства Heltec — и ни одной записи для самого T-Deck. Человек,
    копирующий пример в `secrets.json`, получал файл, которым нельзя настроить плату: скрипт
    просит роль из своего списка, а в примере таких ролей нет.

    Проверяется связь примера со скриптом, который его читает: каждая роль из примера известна
    `provision.py`, каждое поле этой роли есть в примере, и в примере нет полей, которые ни
    одна его роль не использует."""
    import json
    seen = 0
    for name, sub in (("форка", "meshcore-fork"), ("tdeck", "tdeck")):
        ex = ctx.tree / sub / "secrets.example.json"
        pv = ctx.tree / sub / "scripts" / "provision.py"
        if not (ex.is_file() and pv.is_file()):
            continue
        seen += 1
        try:
            data = json.loads(ex.read_text(encoding="utf-8"))
        except Exception as e:
            ctx.check("пример %s — годный JSON" % name, False, str(e))
            continue
        ctx.check("пример %s — годный JSON" % name, True)

        src = pv.read_text(encoding="utf-8")
        radio = re.search(r"RADIO_FIELDS\s*=\s*\[(.*?)\]", src, re.S)
        roles_src = re.search(r"ROLE_FIELDS\s*=\s*\{(.*?)\n\}", src, re.S)
        if not (radio and roles_src):
            ctx.check("в provision.py %s нашлись роли" % name, False,
                      "не разобрать RADIO_FIELDS/ROLE_FIELDS")
            continue
        radio_f = set(re.findall(r'"([^"]+)"', radio.group(1)))
        roles = {}
        for m in re.finditer(r'"([a-z]+)":\s*\[(.*?)\]([^,]*)', roles_src.group(1), re.S):
            fields = set(re.findall(r'"([^"]+)"', m.group(2)))
            if "RADIO_FIELDS" in m.group(3):
                fields |= radio_f
            roles[m.group(1)] = fields

        devices = data.get("devices", {})
        ctx.check("в примере %s есть хотя бы одно устройство" % name, bool(devices),
                  "раздел devices пуст — настроить по такому примеру нечего")
        used = set()
        for dev, body in devices.items():
            role = body.get("role")
            ctx.check("роль %s в примере %s известна provision.py" % (role, name),
                      role in roles,
                      "provision.py знает роли: " + ", ".join(sorted(roles)))
            if role in roles:
                used |= roles[role]

        # Каждое устройство примера обязано быть окружением ЭТОГО проекта. Без этого
        # утверждения проверка пропускала главное: пример, целиком скопированный из соседней
        # прошивки, проходил её — роли-то знакомы обоим provision.py, а вот плат из примера в
        # этом проекте нет, и настроить по нему нечего. Именно так и было у T-Deck.
        ini = (ctx.tree / sub / "platformio.ini")
        envs = set(re.findall(r"^\[env:([^\]]+)\]", ini.read_text(encoding="utf-8"), re.M)) \
            if ini.is_file() else set()
        alien = sorted(b.get("env", "?") for b in devices.values()
                       if b.get("env") not in envs)
        ctx.check("устройства примера %s собираются в этом проекте" % name, not alien,
                  "окружений нет в platformio.ini: " + ", ".join(alien) +
                  " — пример из другой прошивки")

        have = set(data.get("common", {}))
        for body in devices.values():
            have |= {k for k in body if k not in ("role", "env", "port")}
        missing = sorted(f for f in used if f not in have and f != "name")
        ctx.check("пример %s содержит все поля своих ролей" % name, not missing,
                  "нет в примере: " + ", ".join(missing))
        extra = sorted(f for f in have if f not in used)
        ctx.check("в примере %s нет чужих полей" % name, not extra,
                  "лишние, ни одной роли примера не нужны: " + ", ".join(extra))
    if not seen:
        ctx.note("SKIP secrets_example_test: прошивок рядом нет")


def flood_gap_name_test(ctx):
    """Параметр паузы флуда назван базой, и никто не просит паузы короче диапазона.

    Смысл параметра изменился тихо: раньше это была сама пауза, а с тех пор как паузу стали
    брать из всего диапазона FLOOD_RETRY_MIN_MS…MAX_MS, переданное значение — лишь БАЗА,
    которую в этот диапазон зажимают. Имя `gapMs` обещало другое: вызывающий, попросивший
    20 мс, молча получал не меньше 1000. Отсюда два утверждения — имя говорит, что это база,
    и ни один вызывающий не просит значения, которое всё равно будет поднято."""
    hdr = (ctx.core / "include" / "mesh.h").read_text(encoding="utf-8")
    for fn in ("floodSend", "sensorSendMsg"):
        m = re.search(r"void\s+%s\s*\(([^;]*?)\)\s*;" % fn, hdr, re.S)
        ctx.check("%s объявлена в заголовке ядра" % fn, m is not None)
        if not m:
            continue
        args = m.group(1)
        ctx.check("%s: параметр паузы назван базой" % fn,
                  "gapBaseMs" in args and not re.search(r"\bgapMs\b", args),
                  "параметр снова зовётся gapMs — это не пауза, а база, зажатая в диапазон "
                  "флуда: просьба о 20 мс даст не меньше FLOOD_RETRY_MIN_MS")

    # Нижняя граница диапазона: ниже неё просить бессмысленно, значение всё равно поднимут.
    mn = re.search(r"#\s*define\s+FLOOD_RETRY_MIN_MS\s+(\d+)",
                   (ctx.core / "include" / "config.h").read_text(encoding="utf-8"))
    ctx.check("нижняя граница паузы флуда задана числом", mn is not None)
    if not mn:
        return
    floor = int(mn.group(1))

    def top_args(text, at):
        """Аргументы вызова, начинающегося на позиции at (на '('), по верхнему уровню скобок."""
        depth, cur, out = 0, "", []
        for ch in text[at:]:
            if ch in "([":
                depth += 1
                if depth == 1:
                    continue
            elif ch in ")]":
                depth -= 1
                if depth == 0:
                    out.append(cur)
                    return out
            if depth == 1 and ch == ",":
                out.append(cur)
                cur = ""
                continue
            cur += ch
        return out

    bad = []
    roots = [ctx.core] + [ctx.tree / s for s in ("meshcore-fork", "tdeck")]
    for root in roots:
        if not root.is_dir():
            continue
        for f in sorted(root.rglob("*.cpp")):
            if ".pio" in f.parts:
                continue
            txt = f.read_text(encoding="utf-8", errors="replace")
            for fn in ("floodSend", "sensorSendMsg"):
                for m in re.finditer(r"\b%s\s*\(" % fn, txt):
                    if txt[:m.start()].rstrip().endswith(("void", "unsigned", "int")):
                        continue            # это определение, а не вызов
                    a = top_args(txt, m.end() - 1)
                    idx = 3 if fn == "floodSend" else 1
                    if len(a) <= idx:
                        continue
                    v = a[idx].strip()
                    if re.fullmatch(r"\d+", v) and 0 < int(v) < floor:
                        bad.append("%s:%d %s(..., %s, ...)"
                                   % (f.name, txt[:m.start()].count("\n") + 1, fn, v))
    ctx.check("никто не просит паузу короче диапазона флуда", not bad,
              "просят меньше FLOOD_RETRY_MIN_MS=%d и молча получат больше: %s"
              % (floor, "; ".join(bad)))


def tools_ref_branch_test(ctx):
    """`tools.ref` держит имя ветки, а не пин, — и это решение владельца.

    В `core.ref` лежит тег (пин на версию ядра), а в `tools.ref` — имя ветки. Разница не
    случайная: владельцу предлагали три варианта (оставить ветку, пинить на коммит, пинить на
    тег), и он выбрал ветку. Цена известна и принята — правка проверок меняет результат сборки
    прошивки, которую никто не трогал; выгода — свежие проверки действуют на обе прошивки
    сразу, без шага «поднять пин» в двух репозиториях.

    Проверка нужна ровно затем, чтобы пин не появился здесь незаметно: sha или тег в
    `tools.ref` поменяли бы порядок работы молча, и узнать об этом можно было бы только по
    тому, что новая проверка нигде не запускается."""
    seen = 0
    for name, sub in (("форка", "meshcore-fork"), ("tdeck", "tdeck")):
        f = ctx.tree / sub / "tools.ref"
        if not f.is_file():
            continue
        seen += 1
        ref = f.read_text(encoding="utf-8").strip().splitlines()[0].strip() if f.read_text(
            encoding="utf-8").strip() else ""
        ctx.check("tools.ref %s не пуст" % name, bool(ref), "файл пуст — CI не найдёт проверки")
        if not ref:
            continue
        ctx.check("tools.ref %s — не sha коммита" % name,
                  re.fullmatch(r"[0-9a-f]{7,40}", ref) is None,
                  "в tools.ref лежит %s: похоже на пин, а решено держать ветку" % ref)
        ctx.check("tools.ref %s — не тег версии" % name,
                  re.fullmatch(r"v\d+\.\d+\.\d+", ref) is None,
                  "в tools.ref лежит тег %s: решено держать ветку" % ref)
    # core.ref, наоборот, обязан быть пином: иначе прошивка собирается с «чем-то из main».
    for name, sub in (("форка", "meshcore-fork"), ("tdeck", "tdeck")):
        f = ctx.tree / sub / "core.ref"
        if not f.is_file():
            continue
        ref = f.read_text(encoding="utf-8").strip().splitlines()[0].strip()
        ctx.check("core.ref %s — тег версии ядра" % name,
                  re.fullmatch(r"v\d+\.\d+\.\d+", ref) is not None,
                  "в core.ref лежит %s, а не тег: прошивка собралась бы «чем-то из main»" % ref)
    if not seen:
        ctx.note("SKIP tools_ref_branch_test: прошивок рядом нет")


def sensor_tasks_in_core_test(ctx):
    """Расписание задач узла живёт в ядре, а платформенное из него — за хуками.

    `sensor_tasks.cpp` лежал двумя копиями в `lib/meshcore` каждой прошивки и успел
    разойтись — при том что из 68 строк платформенными были ровно три вызова: экран, кнопка и
    телефонное приложение. Остальное (расписание heartbeat, сторожа сессий, переключение
    частоты процессора, откат несохранённых настроек) к плате отношения не имеет.

    Поэтому файл переехал в ядро, а три вызова стали хуками. Проверка следит за обеими
    половинами решения: копий в прошивках нет, и ядро не зовёт платформенное напрямую."""
    core_src = ctx.core / "src" / "sensor_tasks.cpp"
    ctx.check("расписание задач узла лежит в ядре", core_src.is_file(),
              "нет mesh-network-core/src/sensor_tasks.cpp")
    ctx.check("ядро объявляет sensorTasksTick", (ctx.core / "include" / "sensor_tasks.h").is_file(),
              "нет mesh-network-core/include/sensor_tasks.h — прошивке нечего включать")
    if not core_src.is_file():
        return
    txt = core_src.read_text(encoding="utf-8")
    code = "\n".join((ln if ln.find("//") < 0 else ln[:ln.find("//")])
                     for ln in txt.splitlines())

    # Ядро не имеет права знать про экран и приложение иначе как через хуки. Кнопка из этого
    # списка ушла: её логика переехала в ядро следом за расписанием (button_in_core_test), и
    # расписание зовёт buttonTick() напрямую — хук mcButtonTick стал бы пустой пересылкой.
    for direct, hook in (("screenTick", "mcUiTick"),
                         ("companionTick", "mcCompanionTick")):
        ctx.check("ядро зовёт %s, а не %s напрямую" % (hook, direct),
                  hook in code and not re.search(r"(?<!mc)\b%s\s*\(" % direct, code),
                  "в ядре остался прямой вызов %s: это код прошивки, и ядру его не собрать"
                  % direct)
    # button.h из этого списка ушёл: он теперь заголовок ЯДРА, и включать его расписание
    # обязано. Остались заголовки, которые живут только в прошивке.
    for bad in ("display.h", "companion.h"):
        ctx.check("ядро не включает %s" % bad, bad not in txt,
                  "ядро включает заголовок прошивки — он до него не доедет")

    # Копий в прошивках быть не должно: вернувшаяся копия снова разойдётся, и собираться
    # будет именно она (lib/ прошивки перекрывает библиотеку).
    for name, sub in (("форка", "meshcore-fork"), ("tdeck", "tdeck")):
        d = ctx.tree / sub / "lib" / "meshcore"
        if not d.is_dir():
            continue
        for rel in ("src/sensor_tasks.cpp", "include/sensor_tasks.h"):
            ctx.check("у %s нет своей копии %s" % (name, rel), not (d / rel).exists(),
                      "копия вернулась: она перекроет ядро и снова разойдётся с ним")

    # Хук экрана обязаны закрыть обе прошивки: заглушка здесь — экран, который не гаснет.
    for name, sub in (("форка", "meshcore-fork"), ("tdeck", "tdeck")):
        root = ctx.tree / sub
        if not root.is_dir():
            continue
        own = "\n".join(f.read_text(encoding="utf-8")
                        for f in sorted((root / "src").glob("*.cpp")) if f.is_file())
        ctx.check("%s переопределяет mcUiTick" % name,
                  re.search(r"^\s*void\s+mcUiTick\s*\(\s*\)\s*\{", own, re.M) is not None,
                  "без переопределения экран %s не будет гаснуть: сработает заглушка ядра" % name)


def button_in_core_test(ctx):
    """Логика кнопки живёт в ядре, а пин, уровень и экран — за хуками.

    `button.cpp` лежал копией в `lib/meshcore` форка, и из его 130 строк платформенными были
    ровно три вызова: настроить пин с прерыванием, прочитать уровень, переключить экран. Всё
    остальное — смысл нажатия: окно дребезга, кольцо фронтов, счёт серии коротких, порог
    долгого удержания, намеренно пустой промежуток между ними и правило «пока идёт проверка
    доступности, её гасит ЛЮБОЕ короткое нажатие». К плате это отношения не имеет, и держать
    это копией значило повторить историю `sensor_tasks.cpp`.

    Проверка следит за тремя вещами сразу, потому что поломаться может любая:

    1. ядро держит логику и не знает про пин;
    2. прошивка закрывает три хука и отдаёт фронт из обработчика прерывания в ядро;
    3. от переезда не осталось пустой пересылки — хук `mcButtonTick` удалён, расписание зовёт
       `buttonTick()` напрямую под признаком `FEATURE_BUTTON`.
    """
    src = ctx.core / "src" / "button.cpp"
    hdr = ctx.core / "include" / "button.h"
    ctx.check("логика кнопки лежит в ядре", src.is_file(),
              "нет mesh-network-core/src/button.cpp")
    ctx.check("ядро объявляет кнопку", hdr.is_file(),
              "нет mesh-network-core/include/button.h — прошивке нечего включать")
    if not (src.is_file() and hdr.is_file()):
        return
    txt = src.read_text(encoding="utf-8")
    code = "\n".join((ln if ln.find("//") < 0 else ln[:ln.find("//")])
                      for ln in txt.splitlines())

    # --- 1. ядро знает про кнопку только через хуки ---
    for hook, why in (("mcButtonAttach", "настроить пин и повесить прерывание"),
                      ("mcButtonDown", "прочитать уровень для пересинхронизации"),
                      ("mcScreenToggle", "переключить экран на долгом удержании")):
        ctx.check("ядро спрашивает хук %s" % hook,
                  re.search(r"\b%s\s*\(" % hook, code) is not None,
                  "ядро не зовёт %s (%s) — значит делает это само, а пин у плат разный"
                  % (hook, why))
    for bad in ("BUTTON_PIN", "pinMode", "digitalRead", "attachInterrupt", "gpio_get_level",
                "screenToggle"):
        ctx.check("ядро не трогает %s" % bad,
                  re.search(r"\b%s\b" % bad, code) is None,
                  "в ядре осталось платформенное обращение %s: на плате без этого пина ядро "
                  "не собрать, а на другой плате он другой" % bad)

    # --- отказ платы уважается ---
    # Не формальность: признак включали на плате без кнопки, и digitalRead на пине -1 отдавал
    # LOW, то есть «кнопка нажата навсегда». Теперь плата отвечает отказом, и ядро обязано
    # замолчать, а не разбирать пустое кольцо.
    begin = ctx.grab(src, "void buttonBegin(")
    # Именно ПРИСВАИВАНИЕ, а не вызов: проверка «mcButtonAttach() упоминается в buttonBegin»
    # проходила и после отката, в котором ответ хука выбрасывался, — то есть не проверяла
    # ничего. Откат это и показал.
    ctx.check("buttonBegin запоминает ответ платы",
              re.search(r"btnAttached\s*=\s*mcButtonAttach\s*\(", begin) is not None,
              "buttonBegin зовёт хук и выбрасывает ответ — отказ платы ни на что не влияет")
    tick = ctx.grab(src, "void buttonTick(")
    ctx.check("buttonTick молчит, когда платы нет",
              re.search(r"if\s*\(\s*!\s*btnAttached\s*\)\s*return\s*;", tick) is not None,
              "buttonTick не выходит при отказе платы: кнопки нет, а фронты разбираются")

    # --- обработчик прерывания держит только защёлку ---
    isr = ctx.grab(src, "void IRAM_ATTR buttonEdgeCaptured(")
    ctx.check("защёлка фронта лежит в IRAM", "IRAM_ATTR" in txt,
              "buttonEdgeCaptured без IRAM_ATTR: обработчик может сработать во время операции "
              "с флешем, и код должен быть в IRAM")
    for bad in ("millis", "Serial", "mcButtonDown", "buttonEdge("):
        ctx.check("защёлка не зовёт %s" % bad, bad not in isr,
                  "в защёлке фронта вызов %s: из прерывания так делать нельзя" % bad)

    # --- 2. прошивка закрывает хуки и отдаёт фронт ядру ---
    fork = ctx.tree / "meshcore-fork"
    if not fork.is_dir():
        ctx.note("     meshcore-fork рядом нет — железная половина кнопки не проверяется")
    else:
        own = fork / "src" / "mc_platform.cpp"
        ctx.check("железная половина кнопки у форка на месте", own.is_file(),
                  "нет meshcore-fork/src/mc_platform.cpp")
        if own.is_file():
            o = own.read_text(encoding="utf-8")
            for hook in ("mcButtonAttach", "mcButtonDown", "mcScreenToggle"):
                ctx.check("форк переопределяет %s" % hook,
                          re.search(r"(?m)^(?:void|bool)\s+%s\s*\(" % hook, o) is not None,
                          "без переопределения сработает заглушка ядра: кнопки у платы как "
                          "будто нет (%s)" % hook)
            # Обработчик обязан отдавать фронт в ядро, иначе кольцо пустое навсегда.
            ctx.check("обработчик прерывания форка отдаёт фронт ядру",
                      "buttonEdgeCaptured(" in o,
                      "прошивка защёлкивает фронты у себя: ядро их не увидит")
            ctx.check("обработчик прерывания форка лежит в IRAM",
                      re.search(r"IRAM_ATTR\s+\w*[Ii]sr\s*\(", o) is not None,
                      "обработчик без IRAM_ATTR — он может сработать во время операции с флешем")
        # Копия в прошивке перекрыла бы ядро: lib/ прошивки сильнее библиотеки.
        for rel in ("src/button.cpp", "include/button.h"):
            ctx.check("у форка нет своей копии %s" % rel,
                      not (fork / "lib" / "meshcore" / rel).exists(),
                      "копия вернулась: она перекроет ядро и снова разойдётся с ним")

    # --- 3. пустой пересылки не осталось ---
    plat = (ctx.core / "include" / "mc_platform.h").read_text(encoding="utf-8")
    ctx.check("хука mcButtonTick в контракте нет",
              re.search(r"(?m)^\s*void\s+mcButtonTick\s*\(\s*\)\s*;", plat) is None,
              "mcButtonTick вернулся в контракт: он пересылал вызов в прошивку, а логика "
              "кнопки теперь в ядре — пересылать некуда")
    tasks = ctx.core / "src" / "sensor_tasks.cpp"
    if tasks.is_file():
        t = tasks.read_text(encoding="utf-8")
        ctx.check("расписание зовёт кнопку напрямую",
                  re.search(r"(?m)^\s*buttonTick\s*\(\s*\)\s*;", t) is not None,
                  "расписание не зовёт buttonTick(): нажатия не разбираются вовсе")
        # Под признаком, а не безусловно: на плате без кнопки файла кнопки в сборке нет.
        ctx.check("вызов кнопки стоит под FEATURE_BUTTON",
                  re.search(r"#if\s+FEATURE_BUTTON\s*\n\s*buttonTick\s*\(\s*\)\s*;", t)
                  is not None,
                  "buttonTick() зовётся без #if FEATURE_BUTTON: на плате без кнопки это "
                  "ссылка на функцию, которой в сборке нет")


def relay_policy_test(ctx):
    """Правила переиздания — перенос из оригинального MeshCore, и перенос честный.

    Политика взята из meshcore-dev/MeshCore (лицензия MIT): `isFloodHopLimitExceeded` из
    src/helpers/RoutingPolicy.h, `isLooped`, таблицы `max_loop_*` и `getRetransmitDelay` из
    examples/simple_repeater/MyMesh.cpp. Решения проверяются на хосте (relay_queue_test);
    здесь проверяется то, что из поведения не видно: согласованность чисел между собой,
    отсутствие фильтра по типу нагрузки и уведомление об авторстве.

    Числа скопированы НЕ все, и это тоже проверяется. Общий предел хопов у оригинала 64, а
    счётчик хопов занимает шесть бит — больше 63 не бывает ни у них, ни у нас, то есть их
    число не срабатывает никогда. Скопировать его значило бы тихо выключить работающую
    проверку, поэтому общий предел остался нашим."""
    cfg = (ctx.core / "include" / "config.h").read_text(encoding="utf-8")
    rel = (ctx.core / "src" / "mesh_relay.cpp").read_text(encoding="utf-8")

    def const(name):
        m = re.search(r"(?m)^#define\s+%s\s+(\d+)\b" % name, cfg)
        return int(m.group(1)) if m else None

    names = ("RELAY_DELAY_MIN_MS", "RELAY_DELAY_MAX_MS", "RELAY_TX_DELAY_PCT",
             "RELAY_DELAY_SPREAD", "RELAY_FLOOD_MAX", "RELAY_FLOOD_MAX_ADVERT",
             "FRAME_AIRTIME_MS")
    vals = {n: const(n) for n in names}
    missing = [n for n, v in vals.items() if v is None]
    ctx.check("числа политики переиздания заданы", not missing,
              "не найдено в config.h: " + ", ".join(missing))
    if missing:
        return

    # 1. Объявленный бюджет задержки обязан совпадать с формулой, по которой она считается.
    #    Литералом он оставлен затем, что его читают проверки и чужие таймауты; но литерал,
    #    разошедшийся с формулой, — это обещание, которого код не держит.
    t = (vals["FRAME_AIRTIME_MS"] * vals["RELAY_TX_DELAY_PCT"]) // 100
    want = vals["RELAY_DELAY_MIN_MS"] + vals["RELAY_DELAY_SPREAD"] * t
    ctx.check("бюджет задержки переиздания совпадает с формулой (%d мс)" % want,
              vals["RELAY_DELAY_MAX_MS"] == want,
              "RELAY_DELAY_MAX_MS = %d, а формула даёт %d + %d * (%d * %d / 100) = %d"
              % (vals["RELAY_DELAY_MAX_MS"], vals["RELAY_DELAY_MIN_MS"],
                 vals["RELAY_DELAY_SPREAD"], vals["FRAME_AIRTIME_MS"],
                 vals["RELAY_TX_DELAY_PCT"], want))

    # 2. Предел объявлений обязан быть СТРОГО меньше общего: равный ничего не добавляет.
    ctx.check("у объявлений свой предел хопов, и он строже общего",
              vals["RELAY_FLOOD_MAX_ADVERT"] < vals["RELAY_FLOOD_MAX"],
              "advert %d против общего %d: отдельное число не отсекает ничего"
              % (vals["RELAY_FLOOD_MAX_ADVERT"], vals["RELAY_FLOOD_MAX"]))

    # 3. Общий предел обязан быть достижим: счётчик хопов шестибитный, выше 63 не бывает.
    ctx.check("общий предел хопов достижим (<= 63)", vals["RELAY_FLOOD_MAX"] <= 63,
              "RELAY_FLOOD_MAX = %d, а в path_len под число хопов шесть бит — предел не "
              "сработает никогда, и ограничителем останется только размер кадра"
              % vals["RELAY_FLOOD_MAX"])

    # 4. Задержка выводится из времени ЭТОГО кадра, а не из константы.
    delay = ctx.grab(ctx.core / "src/mesh_relay.cpp", "unsigned long relayDelayMs(")
    ctx.check("задержка переиздания выводится из времени кадра",
              "radioAirtimeMs(" in delay,
              "relayDelayMs не спрашивает время кадра: задержка снова одна на все размеры")
    ctx.check("задержка переиздания не выходит за объявленный бюджет",
              "RELAY_DELAY_MAX_MS" in delay,
              "relayDelayMs не ограничен RELAY_DELAY_MAX_MS, а из него выведены чужие "
              "таймауты ожидания")

    # 5. Таблицы допусков петли: строгая — все единицы, и с ростом хэша допуск не растёт.
    tables = {}
    for name in ("relayLoopMinimal", "relayLoopModerate", "relayLoopStrict"):
        m = re.search(r"%s\[\]\s*=\s*\{([^}]*)\}" % name, rel)
        if not m:
            tables[name] = None
            continue
        # Комментарии внутри таблицы выкидываем: в них стоят номера размеров хэша
        # (/* 1 Б */, /* 2 Б */), и без этого в список допусков попадали они.
        body = re.sub(r"/\*.*?\*/", "", m.group(1), flags=re.S)
        tables[name] = [int(x) for x in re.findall(r"(?<![\w.])(\d+)(?![\w.])", body)]
    ctx.check("таблицы допусков петли на месте", all(tables.values()),
              "не разобрались: " + ", ".join(n for n, v in tables.items() if not v))
    if all(tables.values()):
        ctx.check("строгий уровень не допускает повторов",
                  tables["relayLoopStrict"][1:] == [1] * len(tables["relayLoopStrict"][1:]),
                  "строгий уровень разрешает больше одного вхождения: %s"
                  % tables["relayLoopStrict"])
        for name in ("relayLoopMinimal", "relayLoopModerate"):
            row = tables[name][1:]
            ctx.check("допуск %s не растёт с размером хэша" % name,
                      all(a >= b for a, b in zip(row, row[1:])),
                      "%s = %s: чем длиннее хэш, тем МЕНЬШЕ случайных совпадений, значит "
                      "допуск обязан сужаться" % (name, tables[name]))
    ctx.check("уровень определения петли объявлен",
              const("RELAY_LOOP_DETECT") is not None
              or re.search(r"(?m)^#define\s+RELAY_LOOP_DETECT\s+RELAY_LOOP_\w+", cfg)
              is not None,
              "RELAY_LOOP_DETECT не задан — уровень строгости выбирать нечем")

    # 6. По типу нагрузки переиздание не фильтруется. Раньше фильтр был, с подписью
    #    «транспортные коды», и отбрасывал REQ и ACK: подтверждения доставки через нас не
    #    проходили. Разрешено ровно два упоминания типа: предел объявлений и личка себе.
    decide = ctx.grab(ctx.core / "src/mesh_relay.cpp", "int maybeQueueRelay(")
    code = "\n".join((ln if ln.find("//") < 0 else ln[:ln.find("//")])
                      for ln in decide.splitlines())
    bad = [m for m in re.findall(r"payload_type\s*(?:==|!=)\s*(\w+)", code)
           if m not in ("PAYLOAD_TYPE_TXT_MSG",)]
    ctx.check("по типу нагрузки переиздание не фильтруется", not bad,
              "в решении сравнение типа нагрузки с %s: репитер переносит, а не выбирает, и "
              "так уже терялись ACK" % ", ".join(bad))

    # 7. Уведомление об авторстве обязано ехать с кодом: он скопирован под MIT.
    for path, txt in ((ctx.core / "src/mesh_relay.cpp", rel),
                      (ctx.core / "include/config.h", cfg)):
        ctx.check("в %s есть ссылка на источник правил" % path.name,
                  "MIT" in txt and "MeshCore" in txt,
                  "код правил переиздания скопирован из оригинального MeshCore под MIT — "
                  "уведомление об авторстве обязано остаться в файле")


def relay_queue_test(ctx):
    """Решения ретранслятора по кадру.

    maybeQueueRelay — чистая функция от байтов кадра, поэтому её можно вырезать и прогнать
    на хосте. Проверяем в том числе главный баг: переполненная очередь обязана возвращать
    NOROOM и НЕ запоминать хэш кадра. Запомнив, узел отбрасывал все оставшиеся копии
    отправителя как дубликаты — то есть терял кадр целиком, а не на один залп."""
    if not shutil.which("g++"):
        print("SKIP g++ не найден — решения ретранслятора не проверены")
        return
    code = (RELAY_PRELUDE
            + ctx.span(ctx.core / "src/mesh_relay.cpp",
                   "static struct {", "static int relaySeenNext = 0;")
            + "\n" + ctx.grab(ctx.core / "src/mesh_relay.cpp", "static bool relayWasQueued(") + "\n"
            + ctx.span(ctx.core / "src/mesh_relay.cpp",
                       "static const uint8_t relayLoopMinimal[]",
                       "relayLoopStrict[]   = { 0, /* 1 \u0411 */ 1, /* 2 \u0411 */ 1, "
                       "/* 3 \u0411 */ 1 };") + "\n"
            + ctx.grab(ctx.core / "src/mesh_relay.cpp", "bool relayFloodHopLimitExceeded(") + "\n"
            + ctx.grab(ctx.core / "src/mesh_relay.cpp", "bool relayIsLooped(") + "\n"
            + ctx.grab(ctx.core / "src/mesh_relay.cpp", "unsigned long relayDelayMs(") + "\n"
            + ctx.grab(ctx.core / "src/mesh_relay.cpp", "static void relayMarkQueued(") + "\n"
            + ctx.grab(ctx.core / "src/mesh.cpp", "static bool meshFrameHash(") + "\n"
            + ctx.grab(ctx.core / "src/mesh.cpp", "bool meshFrameHashOf(") + "\n"
            + ctx.grab(ctx.core / "src/mesh_relay.cpp", "int maybeQueueRelay(") + "\n"
            + ctx.grab(ctx.core / "src/mesh_relay.cpp", "void meshRelayTick(") + "\n"
            + RELAY_MAIN)
    # Хэш считается через mbedtls; подменяем его собственным, иначе на хосте не соберётся
    code = code.replace("""    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, &pt, 1);
    mbedtls_md_update(&ctx, &data[offset], len - offset);
    mbedtls_md_finish(&ctx, out);
    mbedtls_md_free(&ctx);""",
                        """    MdCtx ctx;
    md_starts(&ctx);
    md_update(&ctx, &pt, 1);
    md_update(&ctx, &data[offset], len - offset);
    md_finish(&ctx, out);""")
    if "mbedtls_md_starts" in code:
        ctx.check("подмена mbedtls в тесте ретранслятора", False,
              "вид функции meshFrameHash изменился — подмена не сработала, проверка фиктивна")
        return
    exe, build = ctx.host_build(code, "r.cpp")
    if exe is None:
        ctx.check("сборка теста решений ретранслятора", False, build[:500])
        return
    run = subprocess.run([str(exe)], capture_output=True, text=True)
    ctx.check("решения ретранслятора (дубли, петли, битые кадры, переполнение очереди)",
          run.returncode == 0, (run.stdout + run.stderr).strip()[:600])


def handshake_budget_test(ctx):
    """Рукопожатия стоят в чужих бюджетах, и это не видно по числам.

    Сенсор отвечает на ota:start копиями ackstart, пока ещё в обычном канале. Раньше он звал
    sensorSendMsg(OTA_ACKSTART, 20) — 20 мс была САМОЙ паузой. После того как пауза флуда
    стала диапазоном FLOOD_RETRY_MIN_MS…MAX с нижней границей 1000 мс, те же 20 мс стали
    базой, которую зажали вниз: три копии растянулись на 2–4.6 с. За это время успевал
    сработать сторож сенсора (OTA_SENSOR_FIRST_CHUNK_MS тикает от приёма ota:start), и
    сессия умирала с «no response». Числа в конфиге были правильные, сломалась связка между
    ними и местом, где они тратятся.

    Проверяем, что ни один вызов отправки не растягивает эфир дольше бюджета приёмника:
    повторов больше FLOOD_REPEATS в обычных сообщениях быть не должно, а ackstart обязан
    уходить отдельной отправкой с короткой паузой."""
    cfg = (ctx.core / "include/config.h").read_text(encoding="utf-8")

    def const(name):
        m = re.search(r"^#define\s+%s\s+(\d+)\b" % name, cfg, re.M)
        return int(m.group(1)) if m else None

    flood_min = const("FLOOD_RETRY_MIN_MS")
    airtime = const("FRAME_AIRTIME_MS")
    first_chunk = const("OTA_SENSOR_FIRST_CHUNK_MS")
    settle = const("OTA_FAST_SETTLE_MS")
    ack_copies = const("OTA_ACKSTART_COPIES")
    ack_gap = const("OTA_ACKSTART_GAP_MS")
    ok = all(v is not None for v in (flood_min, airtime, first_chunk, settle,
                                     ack_copies, ack_gap))
    if not ok:
        ctx.check("бюджет рукопожатий: числа найдены", False,
              "нет одного из FLOOD_RETRY_MIN_MS, FRAME_AIRTIME_MS, "
              "OTA_SENSOR_FIRST_CHUNK_MS, OTA_FAST_SETTLE_MS, OTA_ACKSTART_*")
        return

    # ackstart не должен идти через паузу флуда
    rx = (ctx.core / "src/ota_receiver.cpp").read_text(encoding="utf-8")
    via_flood = re.search(r"sensorSendMsg\(\s*OTA_ACKSTART", rx)
    ctx.check("ackstart не отправляется через паузу флуда", not via_flood,
          "sensorSendMsg(OTA_ACKSTART, ...) берёт FLOOD_RETRY_MIN_MS между копиями, "
          "а бюджет первого чанка %d мс" % first_chunk)

    # и укладываться в окно сторожа с запасом на эфир.
    #
    # Время в эфире берётся по НАСТОЯЩЕЙ длине кадра ackstart, а не по FRAME_AIRTIME_MS: тот
    # описывает самый большой кадр (1979 мс), а ackstart — короткое сообщение, 832 мс. Считая
    # по максимуму, проверка объявляла рукопожатие невыполнимым там, где оно работает, —
    # ровно это и случилось, когда FRAME_AIRTIME_MS исправили с 500 до 2000.
    ack_bytes = const("OTA_ACKSTART_FRAME_MAX")
    prof = radio_profile(ctx, "meshcore-fork") or radio_profile(ctx, "tdeck")
    # Без профиля радио время кадра ackstart посчитать нечем, а подставлять вместо него
    # бюджет самого большого кадра НЕЛЬЗЯ: 96 Б висят в эфире 832 мс против 1979 мс, и
    # проверка объявляла бы рукопожатие невыполнимым. Так и вышло в CI ядра и набора
    # проверок, где прошивок рядом нет вовсе: локально зелено, там красно. Молчание честнее
    # посчитанного не из того.
    if not (ack_bytes and prof):
        ctx.note("     SKIP бюджет рукопожатия: профиля радио рядом нет (нужен "
                 "board_config.h прошивки)")
        ack_air = None
    else:
        ack_air = lora_airtime_ms(ack_bytes, *prof)
        ack_span = ack_copies * ack_air + (ack_copies - 1) * ack_gap
    if ack_air is not None:
        ctx.check("ackstart укладывается в окно первого чанка",
              ack_gap < flood_min and ack_span < first_chunk,
              "копий %d по %d мс + эфир ≈ %d мс, окно %d мс (пауза флуда %d мс)"
              % (ack_copies, ack_gap, ack_span, first_chunk, flood_min))

    # и бот обязан ждать не меньше, чем сенсор тратит на уход в быстрый канал
    if ack_air is not None:
        ctx.check("бот ждёт переключения сенсора не меньше, чем сенсор шлёт ackstart",
              settle >= ack_span - ack_air,
              "OTA_FAST_SETTLE_MS %d, отправка ackstart ≈ %d мс (кадр %s Б, эфир %d мс)"
              % (settle, ack_span, ack_bytes, ack_air))

    # Обычные сообщения: пачка копий по 1000+ мс не должна выглядеть как «несколько копий»
    src_files = list((ctx.core / "src").glob("*.cpp")) + \
        list((ctx.root / "lib/meshcore/src").glob("*.cpp"))
    bad = []
    for path in src_files:
        text = path.read_text(encoding="utf-8")
        for m in re.finditer(r"^\s*(?:sensorSendMsg|floodSend)\s*\((.*?)\)\s*;", text,
                             re.M | re.S):
            args = m.group(1)
            nums = re.findall(r"(?<![\w.])(\d+)(?![\w.])", args)
            if len(nums) >= 3 and int(nums[2]) > 3:
                bad.append("%s: repeats=%s" % (path.name, nums[2]))
    ctx.check("никто не просит больше копий флуда, чем заложено на весь эфир", not bad,
          "; ".join(bad))

    # Медленный режим: узел отвечает через OTA_SLOW_ACK_DELAY_MS, пока флуд ещё шлёт копии.
    # Стартовое сообщение обязано быть одно, иначе подтверждение падает в занятый эфир.
    slow = (ctx.core / "src/ota_slow.cpp").read_text(encoding="utf-8")
    ack_delay = const("OTA_SLOW_ACK_DELAY_MS")
    # Ищем отправку стартового сообщения: snprintf с OTA_SLOW_MSG_START, а сразу после неё
    # вызов sensorSendMsg — именно он и должен брать одну копию.
    calls = []
    for m in re.finditer(r"sensorSendMsg\(([^)]*)\)\s*;", slow):
        calls.append((m.start(), m.group(1).strip()))
    start_idx = slow.find("OTA_SLOW_MSG_START")
    start_single = False
    if start_idx >= 0:
        after = [(pos, args) for pos, args in calls if pos > start_idx]
        if after:
            start_single = after[0][1] == "msg, 0, 1"
    ctx.check("старт медленного режима уходит одной посылкой", start_single,
          "иначе узел отвечает через %d мс в эфир второй копии флуда" % (ack_delay or 0))


def fast_rx_isolation_test(ctx):
    """В быстром режиме meshcore недостижим — ни для какого принятого кадра.

    Две поломки подряд родились в этом месте, и обе стоили работоспособности прошивки по
    быстрому каналу.

    Первая: было `if (быстрый кадр) {...} else if (checkAndMarkSeen(...)) {...}`, потом
    ретрансляцию подняли выше дедупа, цепочка вышла из else и стала общей. Каждый кусок
    образа проходил checkAndMarkSeen (попадал в общий кольцевой буфер дедупа) и
    parseMeshCorePacket, а в конце звался radio.startReceive() — в том числе поверх ещё не
    ушедшего в эфир WACK. Сенсор переставал подтверждать пачки, бот уходил в
    otaBotAbort("no progress").

    Вторая: развилка осталась плоской — `pktLen >= 9 && otaFastMode && магия`. Кадр,
    принятый В БЫСТРОМ РЕЖИМЕ, но короче девяти байт или без магии (битый приём на FSK),
    в неё не попадал и уходил в тот же else, к дедупу и startReceive. То есть дыра была
    закрыта только для целых кадров.

    Поэтому проверяется не порядок условий, а достижимость: внешняя развилка — по
    otaFastMode, и всё meshcore-овское лежит в её else, куда из быстрого режима хода нет."""
    body = ctx.span(ctx.core / "src/radio_rx.cpp", "void radioRxTick()", "\n}\n")
    # комментарии выкидываем: в них и braces, и слова «else» встречаются свободно
    lines = []
    for raw in body.split("\n"):
        i = raw.find("//")
        lines.append((raw if i < 0 else raw[:i]).strip())
    lines = [ln for ln in lines if ln]

    # Глубина скобок ПЕРЕД каждой строкой: у «} else {» она на уровень больше тела ветви,
    # поэтому именно так и узнаётся else того самого if.
    depths = []
    d = 0
    for ln in lines:
        depths.append(d)
        d += ln.count("{") - ln.count("}")

    def find(pred, start=0):
        for i in range(start, len(lines)):
            if pred(lines[i]):
                return i
        return -1

    # Ровно `if (otaFastMode) {`, с открывающей скобкой: ниже в той же функции есть
    # однострочный `if (otaFastMode) fastRxErrors++;` в ветке сорванного захвата, и по
    # префиксу проверка цеплялась за него — то есть могла считать развилку целой, когда её
    # уже нет.
    gate = find(lambda ln: ln == "if (otaFastMode) {")
    ctx.check("быстрый режим отделён внешней развилкой", gate >= 0,
              "в radioRxTick нет `if (otaFastMode)` отдельным условием: развилка снова плоская, "
              "и битый кадр быстрого канала уйдёт в meshcore")
    if gate < 0:
        return
    D = depths[gate]

    # else внешней развилки: всё, что ниже него, к быстрому режиму отношения не имеет.
    alt = find(lambda ln: ln.startswith("} else {"), gate + 1)
    while alt >= 0 and depths[alt] != D + 1:
        alt = find(lambda ln: ln.startswith("} else {"), alt + 1)
    ctx.check("у развилки по быстрому режиму есть else для обычного", alt >= 0,
              "не нашли `} else {` внешней развилки")
    if alt < 0:
        return

    # Сырой кадр разбирается ВНУТРИ быстрой ветви, а не после неё.
    raw_at = find(lambda ln: "RAW_MAGIC0" in ln)
    ctx.check("сырой кадр разбирается внутри быстрой ветви",
              raw_at >= 0 and gate < raw_at < alt and depths[raw_at] >= D + 1,
              "разбор сырого кадра стоит вне `if (otaFastMode)`")

    # Главное: ни дедупа, ни разбора meshcore в быстрой ветви нет ни на какой глубине.
    for name, needle in (("дедуп", "checkAndMarkSeen("),
                         ("разбор meshcore", "parseMeshCorePacket("),
                         ("ретрансляция", "maybeQueueRelay(")):
        inside = [i for i in range(gate + 1, alt) if needle in lines[i]]
        ctx.check("в быстром режиме недостижим %s" % name, not inside,
                  "%s вызывается внутри ветки быстрого режима (строка %r)"
                  % (name, lines[inside[0]] if inside else ""))
        after = [i for i in range(alt + 1, len(lines)) if needle in lines[i]]
        ctx.check("вне быстрого режима %s на месте" % name, bool(after),
                  "%s не нашёлся и в обычной ветке — проверка смотрит не туда" % name)

    # Кадр, выброшенный в быстром режиме, обязан оставить приёмник подписанным: мы ничего
    # не передавали, и без startReceive радио замолчало бы до конца сессии.
    drop = find(lambda ln: ln.startswith("} else {"), raw_at if raw_at > 0 else gate)
    drop = drop if 0 <= drop < alt else -1
    ctx.check("выброшенный кадр быстрого канала переподписывает приём",
              drop >= 0 and any("radio.startReceive()" in lines[i] for i in range(drop, alt)),
              "в ветке «не сырой кадр» нет radio.startReceive() — приёмник оглохнет")
    ctx.check("выброшенный кадр быстрого канала считается",
              drop >= 0 and any("fastRxErrors++" in lines[i] for i in range(drop, alt)),
              "мусор на быстром канале нигде не считается — диагностики не будет")


def timing_budgets_test(ctx):
    """Временные бюджеты согласованы между собой.

    Проверка не про «красивые числа», а про то, чтобы таймаут ответа ПЕРЕКРЫВАЛ худший
    случай, а не уступал ему. Пока ответ на пинг мог прийти позже, чем отправитель
    засчитывал потерю, проверка связи врала на загруженной сети — то есть ровно там, где
    теряются сообщения. Числа заданы в config.h выражениями, поэтому ловятся на
    согласованность, а не на конкретные значения.
    """
    cfg = (ctx.core / "include" / "config.h").read_text(encoding="utf-8")

    def macro(name):
        # Определение может быть многострочным (выражение перенесено на следующую строку
        # с обратной косой чертой), поэтому склеиваем продолжение, а не обрываем на первом
        # переводе строки — иначе проверка видела бы только половину выражения.
        m = re.search(r"^#define\s+" + name + r"[ \t]+(.*?)(?:\\\n(.*))?$", cfg, re.M)
        if not m:
            return None
        parts = [p for p in (m.group(1), m.group(2)) if p]
        return " ".join(p.split("//")[0].strip() for p in parts).strip()

    # Величины, которые обязаны быть числами — иначе расчёт снизу не проверить
    names = ["FRAME_AIRTIME_MS", "CAD_WAIT_BUDGET_MS", "RELAY_DELAY_MAX_MS",
             "PING_REPLY_DELAY_MAX_MS", "FLOOD_REPEATS", "FLOOD_RETRY_MIN_MS",
             "FLOOD_RETRY_MAX_MS"]
    vals = {}
    for n in names:
        raw = macro(n)
        if raw is None or not raw.isdigit():
            ctx.check("бюджет %s определён числом" % n, False, "получено: %r" % raw)
            return
        vals[n] = int(raw)
    ctx.check("бюджеты заданы числами", True)

    airtime = vals["FRAME_AIRTIME_MS"]
    tx_worst = vals["CAD_WAIT_BUDGET_MS"] + airtime
    relay_worst = vals["RELAY_DELAY_MAX_MS"] + tx_worst
    response = vals["PING_REPLY_DELAY_MAX_MS"] + tx_worst + relay_worst

    # 1. Таймаут обязан перекрывать худший случай ответа. Раньше 5000 мс против ~10 с.
    timeout = macro("PING_TIMEOUT_MS")
    if timeout is None or "PING_RESPONSE_WORST_MS" not in timeout:
        ctx.check("таймаут ответа выведен из худшего случая", False,
              "ожидалась ссылка на PING_RESPONSE_WORST_MS, получено: %r" % timeout)
        return
    ctx.check("таймаут ответа выведен из худшего случая, а не задан числом", True)

    # 2. Пауза между копиями обязана быть больше времени в эфире ЭТОГО кадра, иначе
    #    следующая копия ложится на предыдущую и повторы не спасают (было 60 мс при ~500 мс).
    #
    #    Раньше здесь сравнивались два числа: FLOOD_RETRY_MIN_MS против FRAME_AIRTIME_MS. Это
    #    было верно, пока пауза была одна на все размеры кадра. Теперь база паузы берётся из
    #    времени этого кадра в эфире (floodSend), и сравнивать с бюджетом самого большого
    #    кадра стало неправильно: нижняя граница 1000 мс меньше 1979 мс, но паузу большого
    #    кадра она и не задаёт — её задаёт сам кадр.
    #
    #    Правило после правки двустороннее, и обе половины проверяются:
    #      * нижняя граница закрывает КОРОТКИЕ кадры: самый маленький висит в эфире 259 мс, и
    #        пауза обязана быть больше, иначе копии мелких сообщений идут залпом;
    #      * потолок FLOOD_RETRY_MAX_MS закрывает БОЛЬШИЕ (airtime_budget_test): зажим не
    #        должен опускать базу ниже времени кадра.
    prof = radio_profile(ctx, "meshcore-fork") or radio_profile(ctx, "tdeck")
    small_air = lora_airtime_ms(16, *prof) if prof else 0
    if vals["FLOOD_RETRY_MIN_MS"] <= small_air:
        ctx.check("пауза между копиями больше времени короткого кадра в эфире", False,
              "нижняя граница паузы %d мс, а кадр 16 Б висит %d мс"
              % (vals["FLOOD_RETRY_MIN_MS"], small_air))
        return
    if vals["FLOOD_RETRY_MAX_MS"] < airtime:
        ctx.check("потолок паузы не режет самый большой кадр", False,
              "FLOOD_RETRY_MAX_MS %d мс, бюджет кадра %d мс: зажим опустит паузу большого "
              "кадра ниже его эфира" % (vals["FLOOD_RETRY_MAX_MS"], airtime))
        return
    ctx.check("пауза между копиями: %d…%d мс против эфира %d…%d мс"
          % (vals["FLOOD_RETRY_MIN_MS"], vals["FLOOD_RETRY_MAX_MS"], small_air, airtime), True)

    # 3. Повторов должно быть больше одного — с одной копией любая помеха равна потере.
    if vals["FLOOD_REPEATS"] < 2:
        ctx.check("копий флуда больше одной", False, "копий: %d" % vals["FLOOD_REPEATS"])
        return
    ctx.check("копий флуда: %d" % vals["FLOOD_REPEATS"], True)

    # 4. Режим проверки доступности не должен накрывать предыдущий обмен: интервал между
    #    запросами обязан быть больше «передача запроса + ожидание ответа».
    cycle = macro("PING_MODE_INTERVAL_MS")
    interval = macro("PING_MODE_CYCLE_MS")
    if not cycle or not interval or "PING_MODE_CYCLE_MS" not in cycle:
        ctx.check("интервал режима проверки выведен из бюджета", False,
              "получено: интервал=%r цикл=%r" % (cycle, interval))
        return
    ctx.check("интервал режима проверки выведен из бюджета, а не задан числом", True)

    # 5. Таймаут ожидания подтверждения медленной прошивки обязан перекрывать окно ответа
    #    вместе с переизданием: узел отвечает не сразу после чанка.
    ack_to = macro("OTA_SLOW_ACK_TIMEOUT_MS")
    resp = macro("OTA_SLOW_RESP_MS")
    if not ack_to or "OTA_SLOW_RESP_MS" not in str(ack_to):
        ctx.check("таймаут подтверждения медленной прошивки выведен из окна ответа", False,
              "получено: %r" % ack_to)
        return
    if resp and "RELAY_DELAY_MAX_MS" not in resp and "FRAME_AIRTIME_MS" not in resp:
        ctx.check("окно ответа медленной прошивки учитывает ретрансляцию", False,
              "получено: %r" % resp)
        return
    ctx.check("таймаут подтверждения медленной прошивки выведен из окна ответа", True)

    # Печатаем сводку: по ней видно, во сколько раз выросли бюджеты и почему.
    print("     сводка: кадр в эфире %d мс, ожидание канала ≤%d мс, передача ≤%d мс,"
          % (airtime, vals["CAD_WAIT_BUDGET_MS"], tx_worst))
    print("             худший ответ %d мс, таймаут с запасом >%d мс, цикл проверки ~%d мс"
          % (response, response, tx_worst + response))


def ota_slow_test(ctx):
    """Медленная прошивка: объявленный размер, порядок проверки и номер чанка.

    Все три проверки закрывают ошибки, из-за которых медленный режим не мог завершиться ни
    при каких условиях. Проверяется устройство кода, а не поведение: сессия идёт часами,
    трогает флеш и радио, и прогнать её на хосте нельзя — но каждая из трёх ошибок видна в
    исходнике однозначно.
    """
    src_path = ctx.core / "src/ota_slow.cpp"
    if not src_path.is_file():
        ctx.check("ota_slow.cpp найден", False, str(src_path))
        return

    # --- 1. Узлу объявляется размер РАСПАКОВАННОГО образа ---
    # Здесь стоял otaFwSize — длина СЖАТОГО потока плюс хвост нулей. Приёмник открывал
    # раздел под него, обрезал по нему распакованный поток, длина сходилась ровно, а CRC32
    # считается по полному образу и не совпадал никогда.
    start = ctx.grab(src_path, "bool otaSlowStart(")
    m = re.search(r"otaSlowTotal\s*=\s*(\w+)\s*;", start)
    ctx.check("медленный режим объявляет размер образа", m is not None,
              "в otaSlowStart нет присваивания otaSlowTotal")
    if m:
        ctx.check("объявляется размер РАСПАКОВАННОГО образа, а не сжатого потока",
                  m.group(1) == "otaImgSize",
                  "otaSlowTotal = %s; сжатый размер узлу не годится — он им открывает "
                  "раздел и проверяет CRC" % m.group(1))

    # ...и это объявление должно быть видно самому ядру: раньше otaImgSize объявлялся только
    # в заголовке прошивки, и файл ядра его не видел — отсюда и подстановка otaFwSize.
    ota_h = (ctx.core / "include/ota.h").read_text(encoding="utf-8")
    ctx.check("otaImgSize объявлен в заголовке ядра",
              re.search(r"extern\s+uint32_t\s+otaImgSize\s*;", ota_h) is not None,
              "в include/ota.h ядра нет extern uint32_t otaImgSize")

    # Числа не равны и не близки — значит путаница фатальна, а не косметична. Считаем на
    # данных, похожих на прошивку (много повторов), а не на случайных: случайные не жмутся.
    img = (b"\x00" * 64 + b"MBFW:h3:0.0.0" + bytes(range(256))) * 400
    stream = zlib.compress(img, 9)
    cfg = (ctx.core / "include/config.h").read_text(encoding="utf-8")
    pad = re.search(r"#define\s+OTA_Z_TAIL_PAD\s+(\d+)", cfg)
    announced_wrong = len(stream) + (int(pad.group(1)) if pad else 0)
    ctx.check("сжатый и распакованный размеры расходятся в разы",
              announced_wrong * 2 < len(img),
              "образ %d Б, поток %d Б — на таких данных подмена была бы незаметна"
              % (len(img), announced_wrong))

    # --- 2. Приёмник проверяет образ раньше, чем подтвердит его ---
    rx = ctx.grab(src_path, "void otaSlowRxData(")
    end_at = rx.find("otaSlowStreamEnd(true)")
    ack_at = rx.find("slowRxAckNow(")
    off_at = rx.find("slowRxOn = false")
    ctx.check("приёмник вообще проверяет образ перед применением", end_at >= 0,
              "в otaSlowRxData нет otaSlowStreamEnd(true)")
    if end_at >= 0 and ack_at >= 0:
        ctx.check("подтверждение уходит ПОСЛЕ проверки образа", end_at < ack_at,
                  "«принял всё» уходит в эфир раньше проверки — ведущий заканчивает сессию "
                  "довольным на несошедшемся образе")
    # otaSlowRxAbort выходит по `if (!slowRxOn) return;`, поэтому гасить флаг до отказа —
    # значит проглотить отказ целиком: ни ota:sfail в эфир, ни строки на экран.
    abort_src = ctx.grab(src_path, "void otaSlowRxAbort(")
    ctx.check("отказ приёмника защищён флагом сессии",
              re.search(r"if\s*\(\s*!\s*slowRxOn\s*\)\s*return\s*;", abort_src) is not None,
              "в otaSlowRxAbort нет проверки slowRxOn — проверка ниже потеряла смысл")
    if end_at >= 0 and off_at >= 0:
        ctx.check("флаг сессии гаснет ПОСЛЕ проверки образа", end_at < off_at,
                  "slowRxOn снят раньше проверки — otaSlowRxAbort выйдет на первой строке, "
                  "и отказ не дойдёт ни до ведущего, ни до экрана")

    # --- 3. Номер отправленного чанка не переживает сессию ---
    tick = ctx.grab(src_path, "void otaSlowTick(")
    ctx.check("номер чанка не статический внутри otaSlowTick",
              re.search(r"\bstatic\b", tick) is None,
              "статическая переменная переживает сессию: вторая сессия за включение начнёт "
              "окно не с нулевого чанка, и узел её не догонит")
    ctx.check("номер чанка сбрасывается на старте сессии",
              re.search(r"otaSlowSent\s*=\s*0\s*;", start) is not None,
              "в otaSlowStart нет сброса otaSlowSent")


def _block_after(src, needle):
    """Текст блока в фигурных скобках, открывающегося сразу за первым вхождением needle.

    Нужно там, где проверяется не функция, а кусок внутри неё: у otaSlowRxStart ветка «приём
    уже идёт» обязана выйти раньше otaSlowStreamBegin, и по всему исходнику это не различить.
    """
    at = src.find(needle)
    if at < 0:
        return None
    start = src.find("{", at)
    if start < 0:
        return None
    depth = 0
    for i in range(start, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[start:i + 1]
    return None


def ota_slow_recovery_test(ctx):
    """Медленная сессия переживает потерю одной посылки.

    Три ошибки, из-за которых одна потерянная посылка стоила всей сессии, а медленный режим
    бывает единственным способом дотянуться до дальнего узла:

    1. объявление `ota:slow:` уходило одной посылкой навсегда — потерялось, и узел не в
       сессии: чанки для него чужие сообщения, он выбрасывает их молча, а ведущий двадцать
       раз повторяет окно в пустоту;
    2. узел отвечал только на чанк с номером БОЛЬШЕ ожидаемого, то есть на повтор уже
       записанного молчал: одно потерянное подтверждение вешало сессию намертво;
    3. повторное объявление того же образа звало otaSlowStreamBegin → Update.begin() поверх
       открытой сессии, и узел уходил в отказ вместо продолжения. С правкой 1 повторные
       объявления стали штатными, то есть без этой правки ломается всё, что чинит первая.

    Проверяется устройство кода, а не поведение — как в ota_slow_test: сессия идёт часами,
    трогает флеш и радио, и прогнать её на хосте нельзя. Но каждая ошибка видна в исходнике
    однозначно, и на каждую проверку ниже есть свой откат.
    """
    src_path = ctx.core / "src/ota_slow.cpp"
    if not src_path.is_file():
        ctx.check("ota_slow.cpp найден", False, str(src_path))
        return
    src = src_path.read_text(encoding="utf-8")
    start = ctx.grab(src_path, "bool otaSlowStart(")
    tick = ctx.grab(src_path, "void otaSlowTick(")

    # --- 1. Объявление сессии зовётся из двух мест ---
    # Второе место — повтор окна, и без него правка 1 не работает: потерянный старт
    # по-прежнему теряется, просто вместе с первым окном.
    send = ctx.grab(src_path, "static void otaSlowSendStart(") \
        if "static void otaSlowSendStart(" in src else ""
    ctx.check("объявление сессии вынесено в отдельную функцию", bool(send),
              "в ota_slow.cpp нет otaSlowSendStart — повторять объявление нечем, кроме как "
              "запятан второй копией snprintf в otaSlowStart и otaSlowTick")
    if send:
        ctx.check("старт сессии уходит через otaSlowSendStart()",
                  "otaSlowSendStart()" in start and "OTA_SLOW_MSG_START" not in start,
                  "otaSlowStart зовёт otaSlowSendStart()=%s, а формат объявления в нём сам=%s "
                  "— значит объявление уходит дважды или одной из двух сборок нет"
                  % ("otaSlowSendStart()" in start, "OTA_SLOW_MSG_START" in start))

    call_at = tick.find("otaSlowSendStart()")
    ctx.check("повтор окна объявляет сессию заново", call_at >= 0,
              "в otaSlowTick нет вызова otaSlowSendStart(): потерянный ota:slow: больше не "
              "повторяется, и узел, его не услышавший, не входит в сессию никогда")
    if call_at >= 0:
        # Именно в ветке повтора окна, а не в пути отправки: повторять объявление перед
        # каждым окном — значит лишний трафик в эфире, а ветка повтора и есть «окно не
        # подтвердили». Конец ветки ищем скобками, а не первым же `return;`: первым внутри
        # неё стоит ранний выход по «окно ещё не истекло».
        retry = _block_after(tick, "if (otaSlowAckMs != 0)")
        retry_at = tick.find(retry) if retry else -1
        inside = retry is not None and retry_at <= call_at < retry_at + len(retry)
        ctx.check("объявление повторяется в ветке повтора окна, а не перед отправкой",
                  inside and tick.count("otaSlowSendStart()") == 1,
                  "вызов otaSlowSendStart() в otaSlowTick стоит не в ветке неподтверждённого "
                  "окна либо вызывается больше одного раза (в ветке: %s, вызовов: %d) — "
                  "объявление либо уходит в каждом окне, либо дважды на повторе"
                  % (inside, tick.count("otaSlowSendStart()")))
        # Пока узел не отозвался. Иначе объявление уходит в каждом окне — узел-то уже в
        # сессии, и повторные ota:slow: только занимают эфир.
        ctx.check("объявление повторяется только пока узел не отозвался",
                  re.search(r"if\s*\(\s*!\s*otaSlowHeard\s*\)\s*otaSlowSendStart\s*\(\s*\)\s*;",
                            tick) is not None,
                  "вызов otaSlowSendStart() в otaSlowTick не под условием !otaSlowHeard — "
                  "после первого ответа узла объявление уходит в каждом окне впустую")

    # --- 2. Признак «узел отзывался» живёт всю сессию ---
    # Считать по otaSlowAcked нельзя: узел, ответивший «жду 0», оставляет его нулём, и
    # признак не поднимается никогда — то есть объявление повторялось бы до отказа.
    ctx.check("признак «узел отзывался» объявлен на уровне файла",
              re.search(r"^static\s+bool\s+otaSlowHeard\b", src, re.M) is not None,
              "otaSlowHeard не объявлен на уровне файла static — otaSlowTick и "
              "otaSlowOnAck не увидят одно и то же значение")
    ctx.check("признак «узел отзывался» сбрасывается на старте сессии",
              re.search(r"otaSlowHeard\s*=\s*false\s*;", start) is not None,
              "в otaSlowStart нет `otaSlowHeard = false;` — вторая сессия унаследует признак "
              "от первой и не станет повторять объявление, даже если узел её не услышал")
    ack = ctx.grab(src_path, "void otaSlowOnAck(")
    m = re.search(r"otaSlowHeard\s*=\s*true\s*;", ack)
    ctx.check("любое подтверждение от узла помечает его услышанным", m is not None,
              "в otaSlowOnAck нет `otaSlowHeard = true;` — объявление будет повторяться и "
              "после ответов узла, то есть признак не работает вовсе")
    if m is not None:
        # Отметка ДО разбора номера. Первый ответ узла — это «жду 0», он окно не двигает,
        # и признак, поставленный ниже разбора, не поднялся бы в самой первой сессии.
        ctx.check("отметка ставится ДО разбора номера подтверждения",
                  m.start() < ack.find("next > otaSlowSeq"),
                  "otaSlowHeard помечается после разбора номера: ответ «жду 0» окно не "
                  "двигает, и признак останется снятым на весь первый пакет сессии")

    # --- 3. Узел отвечает на ЛЮБОЕ несовпадение номера чанка ---
    # Как переподтверждает дубликат в TCP: повтор чанка и есть сигнал «он не знает, где я».
    rxdata = ctx.grab(src_path, "void otaSlowRxData(")
    ctx.check("узел отвечает на ЛЮБОЕ несовпадение номера чанка",
              re.search(r"if\s*\(\s*seq\s*!=\s*slowRxExpect\s*\)\s*\{\s*slowRxAckLater\s*\(\s*\)"
                        r"\s*;\s*return\s*;\s*\}", rxdata) is not None,
              "в otaSlowRxData ветка `seq != slowRxExpect` не отвечает через slowRxAckLater() "
              "и выходит — на повтор уже записанного чанка узел молчит, и одно потерянное "
              "подтверждение вешает сессию до отказа по числу повторов")
    ctx.check("старое сужение «отвечаем только на будущем чанке» убрано",
              "seq > slowRxExpect" not in rxdata,
              "в otaSlowRxData осталось условие seq > slowRxExpect: на повтор уже записанного "
              "чанка узел по-прежнему молчит")
    # Ответ отложенный, и заявка не двигается вперёд: иначе переотправленное окно из
    # OTA_SLOW_WINDOW чанков дало бы столько же ответов и забило эфир.
    later = ctx.grab(src_path, "static void slowRxAckLater(")
    ctx.check("отложенное подтверждение не передвигается вперёд повторными заявками",
              re.search(r"if\s*\(\s*slowRxAckDueMs\s*!=\s*0\s*\)\s*return\s*;", later) is not None,
              "в slowRxAckLater нет выхода по уже стоящей заявке: каждое несовпадение "
              "номера в переотправленном окне поставит свою заявку, и узел ответит "
              "OTA_SLOW_WINDOW раз на окно")

    # --- 4. Повторное объявление того же образа продолжает приём ---
    rxstart = ctx.grab(src_path, "void otaSlowRxStart(")
    ctx.check("повторный старт видит, что приём уже идёт",
              re.search(r"if\s*\(\s*slowRxOn\s*\)", rxstart) is not None,
              "otaSlowRxStart не смотрит на slowRxOn и зовёт otaSlowStreamBegin поверх "
              "открытой сессии: Update.begin() вернёт «уже идёт», и узел уйдёт в отказ")
    same = _block_after(rxstart, "if (slowRxOn)")
    if same is not None:
        ctx.check("повтор объявления того же образа продолжает, а не начинает заново",
                  "slowRxAckLater()" in same and "return;" in same
                  and "otaSlowStreamBegin" not in same,
                  "ветка «приём уже идёт» в otaSlowRxStart не отвечает через slowRxAckLater() "
                  "с выходом, либо трогает otaSlowStreamBegin — часы уже принятого выбрасываются")
        # Сверяются все три поля образа. Узел, у которого сверкают не тем полем, объявление
        # СВОЕГО образа посчитает чужим и молча закроет приём.
        pairs = set(re.findall(r"(\w+)\s*==\s*(otaSlow\w+)", same))
        want = {("total", "otaSlowTotal"), ("crc", "otaSlowCrc"), ("chunks", "otaSlowChunks")}
        ctx.check("приёмник сверяет все три поля объявления образа", want <= pairs,
                  "в ветке «приём уже идёт» сравниваются не все поля образа: %s; нет %s"
                  % (", ".join("%s == %s" % p for p in sorted(pairs)) or "ничего",
                     ", ".join("%s == %s" % p for p in sorted(want - pairs))))
    if send and same is not None:
        # Объявление и сверка обязаны говорить об одном образе: поле, добавленное в формат
        # и забытое в сверке, превращает повтор СВОЕГО объявления в объявление чужого.
        # Берём аргументы snprintf и отбрасываем и поля через точку (otaSlowTarget.c_str()),
        # и приведения типа ((unsigned)otaSlowTotal) — нужны только голые имена.
        call = re.search(r"snprintf\s*\((.*?)\)\s*;", send, re.S)
        args = call.group(1) if call else ""
        announced = set(re.findall(r"(?<![\w.])otaSlow\w+\b(?!\s*\.)", args))
        compared = {b for _, b in pairs}
        ctx.check("объявление несёт ровно те поля образа, что сверяет приёмник",
                  bool(announced) and announced == compared,
                  "в otaSlowSendStart в объявление идут %s, а приёмник сверяет %s"
                  % (", ".join(sorted(announced)) or "ничего",
                     ", ".join(sorted(compared)) or "ничего"))

    # --- 5. Размер приходит из эфира, а не из доверенного места ---
    limit = re.search(r"if\s*\(\s*total\s*>\s*OTA_MAX_FW_BYTES\s*\)", rxstart)
    ctx.check("объявленный размер сверяется с пределом", limit is not None,
              "в otaSlowRxStart нет `total > OTA_MAX_FW_BYTES`: размер приходит из эфира, и "
              "с заведомо невозможным числом Update.begin() откажет — но по журналу будет "
              "непонятно, отказала память или образ объявлен чужой")
    begin = rxstart.find("otaSlowStreamBegin(")
    if limit is not None and begin >= 0:
        ctx.check("предел проверяется ДО открытия раздела", limit.start() < begin,
                  "otaSlowStreamBegin() в otaSlowRxStart стоит раньше проверки предела — "
                  "проверка не защищает ничего")
    # Предел обязан быть тот же, что у быстрого режима: «тот же» в комментарии не считается.
    # Поэтому сверяем не наличие проверки, а ИМЯ макроса в обоих местах и то, что он задан
    # числом в конфиге: свой литерал рядом с чужим макросом — это уже два разных предела.
    fast = (ctx.core / "src/ota_receiver.cpp").read_text(encoding="utf-8")
    fast_limit = re.search(r"total\s*>\s*(\w+)", fast)
    slow_limit = re.search(r"total\s*>\s*(\w+)", rxstart)
    cfg_src = (ctx.core / "include/config.h").read_text(encoding="utf-8")
    defined = re.search(r"^#define\s+OTA_MAX_FW_BYTES\s+\(?\s*\d", cfg_src, re.M) is not None
    ctx.check("предел размера общий с быстрым приёмом",
              fast_limit is not None and slow_limit is not None
              and fast_limit.group(1) == slow_limit.group(1) == "OTA_MAX_FW_BYTES"
              and defined,
              "быстрый приём сверяет с %s, медленный — с %s, задано числом в config.h: %s"
              % (fast_limit.group(1) if fast_limit else "ничем",
                 slow_limit.group(1) if slow_limit else "ничем", defined))

    cfg = (ctx.core / "include/config.h").read_text(encoding="utf-8")

    def const(name):
        m = re.search(r"^#define\s+%s\s+(\d+)\b" % name, cfg, re.M)
        return int(m.group(1)) if m else 0

    print("     сводка: окно %d чанков по %d Б, повторов окна до отказа %d, узел отвечает "
          "через ~%d мс" % (const("OTA_SLOW_WINDOW"), const("OTA_SLOW_CHUNK_BYTES"),
                            const("OTA_SLOW_MAX_RETRIES"), const("OTA_SLOW_ACK_DELAY_MS")))


def ota_slow_applied_test(ctx):
    """Потерянный `ota:sdone` больше не выглядит провалом.

    Узел принял последний чанк, проверил образ, отправил `ota:sdone` и перезагрузился в новую
    прошивку. Подтверждение идёт через флуд в момент, когда канал busiest за всю сессию, и
    теряется довольно часто. Дальше ведущий двадцать повторов ждал подтверждения и заканчивал
    «узел не подтверждает»: успешная прошивка докладывалась как провал, а следующая попытка
    шла заново на уже прошитый узел — который после первой попытки ещё и не в сессии, потому
    что перезагрузился.

    Единственное доказательство, что всё сошлось, — heartbeat: узел шлёт привет сразу после
    включения, то есть сразу после применения образа, и версия в нём уже новая. Формат
    сообщений при этом не меняется ни на байт.
    """
    src_path = ctx.core / "src/ota_slow.cpp"
    if not src_path.is_file():
        ctx.check("ota_slow.cpp найден", False, str(src_path))
        return
    start = ctx.grab(src_path, "bool otaSlowStart(")
    tick = ctx.grab(src_path, "void otaSlowTick(")

    # --- 1. Хук heartbeat'а стоит там, где версия уже разобрана ---
    # В otaSlowTick версии нет: она живёт в lastHello, который наполняет sensorRegistryNote.
    # Если вызов уедет из этого места, он либо не скомпилируется, либо (хуже) будет читать
    # предыдущее сообщение — и выдавать чужую версию за версию цели.
    rx = (ctx.core / "src/mesh_rx.cpp").read_text(encoding="utf-8")
    hook_at = rx.find("otaSlowOnHello()")
    note_at = rx.find("sensorRegistryNote()")
    ctx.check("heartbeat цели попадает в сессию из разбора канала",
              hook_at >= 0 and note_at >= 0 and hook_at > note_at,
              "в mesh_rx.cpp вызов otaSlowOnHello() стоит %s, а разбор реестра — %s: версия "
              "должна браться уже разобранной" % (hook_at, note_at))
    hook = ctx.grab(src_path, "void otaSlowOnHello(")
    ctx.check("хук берёт версию из разобранного heartbeat",
              "lastHello.isHello" in hook and "lastHello.ver" in hook,
              "otaSlowOnHello не смотрит lastHello — версию откуда тогда?")
    # Чужое в канале есть всегда: heartbeat шлёт каждый узел, и не один.
    ctx.check("хук принимает heartbeat только от цели",
              re.search(r"if\s*\(\s*lastSender\s*!=\s*otaSlowTarget\s*\)\s*return\s*;", hook)
              is not None,
              "otaSlowOnHello не отбрасывает чужие сообщения: версию соседнего узла можно "
              "принять за версию цели, и прошивка объявится успешной на пустом месте")
    # Узел постарше шлёт в heartbeat просто «hello»: пустой версии там нет смысла читать.
    ctx.check("пустая версия в heartbeat не считается версией",
              re.search(r"lastHello\.ver\.length\(\)\s*==\s*0", hook) is not None,
              "otaSlowOnHello не отбрасывает heartbeat без версии — «hello» без полей "
              "сравнивается с базовой версией и выдаёт чужой успех")
    # Решение — не здесь. Здесь версия запоминается, а вывод делает otaSlowTick, где известно
    # главное условие «весь образ сдан». Решать в хуке нельзя: heartbeat может прийти ДО
    # последнего подтверждения, и тогда успех объявился бы на недокачанном образе.
    ctx.check("хук только запоминает версию, решение принимает не он",
              "otaSlowSeenVer" in hook and "otaSlowDone(" not in hook,
              "otaSlowOnHello зовёт otaSlowDone — решение уехало в разбор heartbeat, где "
              "неизвестно, сдан ли образ целиком")

    # --- 2. Вердикт: одна функция, и она сравнивает с тем, что было ДО сессии ---
    verdict = ctx.grab(src_path, "static bool otaSlowAppliedByHello(")
    for name, field, what in (
            ("otaSlowTargetVer.length() == 0", "otaSlowTargetVer",
             "до сессии версия цели не была известна — сравнивать не с чем"),
            ("otaSlowSeenVer.length() == 0", "otaSlowSeenVer",
             "heartbeat от цели в этой сессии ещё не был")):
        ctx.check("вердикт отказывает, если %s" % what,
                  re.search(re.escape(name) + r"\s*\)\s*return\s+false\s*;", verdict) is not None,
                  "в otaSlowAppliedByHello нет `%s → false`: без этой оговорки признак "
                  "сравнения строк срабатывает на пустых значениях" % name)
    ctx.check("вердикт сравнивает версию ДО сессии с услышанной в сессии",
              re.search(r"return\s+otaSlowSeenVer\s*!=\s*otaSlowTargetVer\s*;", verdict)
              is not None,
              "otaSlowAppliedByHello не возвращает otaSlowSeenVer != otaSlowTargetVer — "
              "значит сравниваются не те поля или направление инвертировано")

    # Обе версии обязаны быть привязаны к сессии: база берётся на старте, а услышанная
    # обнуляется. Унаследованная от прошлой сессии версия объявила бы успех сразу.
    ctx.check("базовая версия цели берётся из реестра на старте сессии",
              re.search(r"otaSlowTargetVer\s*=\s*sensorVersionOf\s*\(", start) is not None,
              "в otaSlowStart нет `otaSlowTargetVer = sensorVersionOf(...)`: сравнивать "
              "не с чем, и вердикт всегда ложь")
    ctx.check("услышанная версия обнуляется на старте сессии",
              re.search(r"otaSlowSeenVer\s*=\s*(\"\"|String\s*\(\s*\))\s*;", start) is not None,
              "в otaSlowStart нет сброса otaSlowSeenVer — версия прошлой сессии переживёт "
              "новую, и первое же подтверждение… то есть первое же сравнение объявит успех")

    # --- 3. Вердикт зовётся там, где образ уже сдан ---
    wait = _block_after(tick, "if (otaSlowSeq >= otaSlowChunks)")
    ctx.check("вердикт зовётся в ветке «весь образ сдан и подтверждён»",
              wait is not None and "otaSlowAppliedByHello()" in wait
              and "otaSlowDone(true" in wait,
              "в otaSlowTick ветка `otaSlowSeq >= otaSlowChunks` не зовёт otaSlowAppliedByHello() "
              "с otaSlowDone(true) — вывод есть, а применить его некому")
    # Считаем ВЫЗОВЫ, а не вхождения подстроки: о вердикте написано в комментарии, и такой
    # подсчёт ругался бы на верный код.
    calls = re.findall(r"(?m)^[ \t]*(?:if\s*\(\s*)?otaSlowAppliedByHello\s*\(\s*\)", tick)
    ctx.check("вердикт не зовётся вне этой ветки", len(calls) == 1,
              "otaSlowAppliedByHello() вызывается из otaSlowTick %d раз: вывод обязан "
              "делаться один раз и после сдачи образа, иначе успех объявится на недокачанном "
              "образе" % len(calls))

    # --- 4. Чтение версии не заводит запись в реестре ---
    reg = ctx.grab(ctx.core / "src/sensor_registry.cpp", "String sensorVersionOf(")
    ctx.check("чтение версии не заводит запись в реестре",
              "sensorSlot(" not in reg,
              "sensorVersionOf зовёт sensorSlot(), а тот ЗАВОДИТ запись: чтение версии у узла, "
              "которого в реестре нет, создаст фантом на странице и в MQTT, а в полном "
              "реестре ещё и вытеснит кого-то живого")
    ctx.check("чтение версии объявлено в заголовке ядра",
              re.search(r"String\s+sensorVersionOf\s*\(",
                        (ctx.core / "include/mesh.h").read_text(encoding="utf-8")) is not None,
              "в include/mesh.h ядра нет объявления sensorVersionOf")

    # --- 5. Журнал говорит, ЧЕМ подтверждён успех ---
    # Без этой строки рядом с «ГОТОВО» стоял бы отладочный «[SLOW] старт» получателя, и
    # по журналу выглядело бы так, будто узел подтвердил сессию сам собой.
    done = ctx.grab(src_path, "void otaSlowDone(")
    ctx.check("на успехе журнал говорит, чем подтверждён итог",
              re.search(r"if\s*\(\s*why\s*&&\s*\*\s*why\s*\)", done) is not None,
              "otaSlowDone на успехе игнорирует why: сессия, завершившаяся по потерянному "
              "ota:sdone, выглядит в журнале так же, как подтверждённая узлом")

    cfg = (ctx.core / "include/config.h").read_text(encoding="utf-8")
    retries = re.search(r"^#define\s+OTA_SLOW_MAX_RETRIES\s+(\d+)", cfg, re.M)
    print("     сводка: сессия ждёт ota:sdone до %s повторов окна, узел отмечается сразу "
          "после включения — запасной путь успевает сработать задолго до отказа"
          % (retries.group(1) if retries else "?"))


# Места, которые обязаны спрашивать «идёт ли ЛЮБАЯ сессия», а не только фазу быстрого режима.
# Список именно перечислением, а не поиском по всем файлам: каждая строка здесь — это
# найденный способ сломать идущую медленную сессию, и добавлять её в список должен человек,
# который понимает, чем это место опасно. Поиск «где ещё остался otaSessionActive» ниже
# отдельной проверкой и тоже не пропустит новое место.
#
# (файл прошивки, имя функции или маркер, чем это опасно для сессии)
ANY_SESSION_SITES = (
    ("lib/meshcore/src/coordinator_tasks.cpp", "coordinatorTasksTick",
     "рассылка времени раз в пять минут падает прямо в фазу данных «маятника»"),
    ("lib/meshcore/src/mqtt.cpp", "/cmd/send",
     "команда из Home Assistant выходит в эфир поверх чанка"),
    ("lib/meshcore/src/web.cpp", "void webTick(",
     "очередь настроек узла выходит в эфир поверх чанка"),
    ("lib/meshcore/src/web.cpp", "void otaHandleSensorsConfig(",
     "настройка узла со страницы уходит в эфир"),
    ("lib/meshcore/src/web.cpp", "void otaHandleSensorsHello(",
     "опрос узлов уходит в эфир"),
    ("lib/meshcore/src/web.cpp", "void otaHandleFwCheck(",
     "проверка обновлений начинает загрузку и может тронуть /ota.bin"),
    ("lib/meshcore/src/fwupdate.cpp", "void fwUpdateTick(",
     "автообновление делает remove + rename /ota.bin под открытым хэндлом сессии"),
    ("lib/meshcore/src/support.cpp", "void supportPingTick(",
     "блокирующий POST останавливает главный цикл на сотни миллисекунд"),
)


def any_session_test(ctx):
    """Медленную сессию не ломает остальная прошивка.

    Медленный режим намеренно не занимает otaPhase, поэтому otaSessionActive() к нему слеп.
    Это и было главной причиной, по которой сессия не доживала до конца: её ломала рассылка
    времени, команда из Home Assistant, автообновление и заливка образа со страницы. Сессия
    идёт ЧАСАМИ — попасть в неё успевает почти всё.

    Проверяется, что опасные места спрашивают otaAnySessionActive(), и что нигде в прошивке
    не осталось otaSessionActive() без пояснения, почему там нужна именно фаза.
    """
    core_ota = (ctx.core / "src/ota.cpp").read_text(encoding="utf-8")
    ctx.check("ядро даёт общий предикат занятости прошивки",
              re.search(r"bool\s+otaAnySessionActive\s*\(\s*\)\s*\{", core_ota) is not None,
              "в ota.cpp ядра нет otaAnySessionActive")

    # Предикат обязан знать про все три состояния: быстрая раздача, быстрый приём, медленный
    # режим. Без приёма он не годится для платы, которая образ ПРИНИМАЕТ, — а её страница
    # тоже умеет писать во флеш.
    body = ctx.grab(ctx.core / "src/ota.cpp", "bool otaAnySessionActive(")
    for name, what in (("otaSessionActive", "быструю раздачу"),
                       ("otaActive", "быстрый приём"),
                       ("otaSlowOn", "медленный режим")):
        ctx.check("общий предикат учитывает %s" % what, name in body,
                  "otaAnySessionActive не смотрит на %s" % name)

    # Предикат должен быть доступен роли-приёмнику: если он определён внутри блока
    # отправителя, плата без раздачи его не слинкует — и проверка выше пройдёт впустую.
    sender_block = core_ota.find("#if FEATURE_MESH_OTA_SENDER")
    sender_end = core_ota.find("#endif // FEATURE_MESH_OTA_SENDER")
    at = core_ota.find("bool otaAnySessionActive()")
    ctx.check("общий предикат доступен и роли-приёмнику",
              not (sender_block < at < sender_end),
              "otaAnySessionActive определён внутри #if FEATURE_MESH_OTA_SENDER — плата, "
              "которая только принимает образ, его не слинкует")

    # Перечисленные места спрашивают общий предикат.
    for rel, marker, danger in ANY_SESSION_SITES:
        path = ctx.tree / "meshcore-fork" / rel
        if not path.is_file():
            continue
        src = path.read_text(encoding="utf-8")
        at = src.find(marker)
        if at < 0:
            ctx.check("место найдено: %s (%s)" % (marker, rel), False,
                      "маркер не найден — проверка ослепла, поправьте ANY_SESSION_SITES")
            continue
        # Смотрим тело от маркера до конца функции (или до следующего определения).
        chunk = src[at:at + 3000]
        ctx.check("%s спрашивает общий предикат" % marker,
                  "otaAnySessionActive()" in chunk, danger)

    # Обратная сторона: нигде не осталось слепого предиката без объяснения. Законных мест
    # ровно два — сам otaSessionActive в ядре и разбор ota:fail быстрой сессии, — и оба
    # помечены словом «фаза» в комментарии рядом.
    stray = []
    for sub in ("meshcore-fork", "tdeck"):
        root = ctx.tree / sub
        if not root.is_dir():
            continue
        for p in sorted(list(root.glob("lib/meshcore/src/*.cpp")) + list(root.glob("src/*.cpp"))):
            txt = p.read_text(encoding="utf-8")
            for m in re.finditer(r"otaSessionActive\s*\(", txt):
                line_start = txt.rfind("\n", 0, m.start()) + 1
                # Пояснение ищем в трёх строках выше вызова.
                before = txt[max(0, line_start - 300):line_start]
                if "фаза" in before or "фазу" in before or "фазе" in before:
                    continue
                line_no = txt.count("\n", 0, m.start()) + 1
                stray.append("%s:%d" % (p.relative_to(ctx.tree), line_no))
    ctx.check("слепой к медленному режиму предикат нигде не остался без объяснения",
              not stray,
              "otaSessionActive() без пояснения про фазу быстрого режима: " + ", ".join(stray))


def weak_hooks_test(ctx):
    """Хук ядра не должен молча остаться заглушкой.

    Ядро зовёт платформенные хуки (`mcUiOtaProgress`, `supportJobStart`, ...), а реализации
    по умолчанию — no-op из `src/mc_platform.cpp`. Если прошивка включила функцию, но хук не
    переопределила, сборка проходит без единого предупреждения, а на плате работает пустышка:
    прогресс OTA не рисуется, «узел занят» всегда «нет». Проверки, которая бы это ловила,
    не было.

    Ловушка тут вовсе не в слове `weak` — с ним всё честно: переопределение честно и
    перекрывает заглушку. Ловушка в трёх местах по соседству:

    - **нет прототипа в `mc_platform.h`.** Фирма пишет свою функцию с тем же именем, но
      ядро о ней не знает: линкер берёт слабую заглушку, а функция прошивки остаётся мёртвым
      кодом. Ни ошибки, ни предупреждения — «работает пустышка»;
    - **своё переопределение помечено `weak`.** Две слабые реализации с одним именем: линкер
      берёт любую. На столе это работает, на плате может не работать, и разница видна только
      в порядке линковки;
    - **вызов есть, а переопределения нет.** Фирма позвала хук в своём коде, но забыла
      переопределить: вызов молча уходит в no-op.

    Плюс список хуков, которые переопределять ОБЯЗАНЫ обе прошивки: экран, прогресс OTA и
    батарея есть у любой платы, и оставленная заглушка здесь — не «фича выключена», а
    сломанный интерфейс. Списка из «обязаны» намеренно нет: GPS есть только у T-Deck, WiFi
    только у форка, и требовать их от обеих плат нельзя.
    """
    hdr_path = ctx.core / "include/mc_platform.h"
    src_path = ctx.core / "src/mc_platform.cpp"
    for p in (hdr_path, src_path):
        if not p.is_file():
            ctx.check("хук ядра на месте: %s" % p.relative_to(ctx.tree), False, str(p))
            return
    hdr = hdr_path.read_text(encoding="utf-8")
    src = src_path.read_text(encoding="utf-8")
    hooks_in_src = _hook_defs(src)
    hooks_in_hdr = _hook_decls(hdr)
    ctx.check("хуков в заглушках не меньше, чем в заголовке",
              hooks_in_hdr and hooks_in_hdr <= set(hooks_in_src),
              "объявлено в mc_platform.h, но заглушки нет: %s"
              % ", ".join(sorted(hooks_in_hdr - set(hooks_in_src)) or "—"))
    ctx.check("каждый хук заглушек помечен weak",
              len(_weak_hooks(src)) == len(hooks_in_src),
              "заглушек %d, помечено weak %d: без признака переопределение из прошивки даст "
              "ошибку линковки вместо тихой подмены" % (len(hooks_in_src), len(_weak_hooks(src))))

    for sub in ("meshcore-fork", "tdeck"):
        # Прошивки может рядом не быть ВООБЩЕ: CI клонирует одну прошивку рядом с ядром, и
        # вторая просто не лежит на диске. Тогда у этой проверки для неё предмета нет — молчание
        # честнее выдуманного «OK» (так и написано в targets.py). А вот прошивка, которая
        # есть, но потеряла обе папки с исходниками, — это поломка, и о ней сказать надо.
        if not (ctx.tree / sub).is_dir():
            ctx.note("     %s рядом нет — хуки не проверяются" % sub)
            continue
        files = _own_sources(ctx, sub)
        if not files:
            ctx.check("прошивка на месте: %s" % sub, False,
                      "каталог %s есть, но нет ни src/, ни lib/meshcore/src/" % sub)
            continue
        strong, weak = set(), set()
        for p in files:
            txt = p.read_text(encoding="utf-8")
            for h in _hook_defs(txt):
                strong.add(h)
                # Признак `weak` идёт строкой выше определения, поэтому смотрим окно перед ним.
                at = txt.find(h)
                if "__attribute__((weak))" in txt[max(0, at - 200):at]:
                    weak.add(h)
        # Переопределение без прототипа — самая дорогая из трёх ловушек: молча, без ошибки.
        # Смотрим только пространство имён ядра (`mc*` и `screenWake`). Префикс `support*`
        # — собственное пространство прикладного кода прошивки (`supportPingTick`,
        # `supportJobTotal`, ...), и его функции хуками ядра не являются: первая версия
        # проверки считала их хуками и объявляла прошивку с ними «переопределяющей то, чего
        # нет в заголовке» — то есть врала, и проверку пришлось бы отключить.
        ctx.check("%s: каждое переопределение объявлено в mc_platform.h" % sub,
                  _reserved_hooks(files) <= hooks_in_hdr,
                  "прошивка переопределяет хуки, которых нет в заголовке ядра: %s — ядро "
                  "линкует свою заглушку, а эти функции остаются мёртвым кодом"
                  % ", ".join(sorted(_reserved_hooks(files) - hooks_in_hdr)))
        ctx.check("%s: переопределения хуков не слабые" % sub, not weak,
                  "помечено weak: %s — линкер возьмёт любую из двух реализаций"
                  % ", ".join(sorted(weak)))
        # Подпись переопределения против прототипа. Именно этот случай для хуков ядра не
        # поймать иначе: у шести хуков префикс `support*` общий с прикладным кодом, отличить
        # их по имени нельзя (см. `_reserved_hooks`), а несовпадение подписи — это ровно то
        # молчаливое откатывание к заглушке, ради которого проверка и написана: имя другое
        # после компиляции, линкер берёт ядро, а функция прошивки остаётся мёртвым кодом без
        # единого предупреждения.
        bad_sig = _sig_mismatch(files, hooks_in_hdr, hdr)
        ctx.check("%s: подписи переопределений совпадают с mc_platform.h" % sub,
                  not bad_sig,
                  "подпись не та: %s — линкер не узнает функцию и возьмёт заглушку ядра"
                  % ", ".join(sorted(bad_sig)))
        # Вызов без переопределения: прошивка сама позвала хук и забыла его закрыть.
        called = set()
        for p in files:
            txt = p.read_text(encoding="utf-8")
            if p.name == "mc_platform.cpp":
                # Раньше этот файл пропускался целиком — и напрасно: в нём не только
                # ОПРЕДЕЛЕНИЯ хуков, но и вызовы (хук интерфейса может спрашивать другой хук).
                # Такой вызов был у T-Deck: mcUiSensorRx спрашивал mcWifiConnected, которого
                # T-Deck не переопределяет, и получал заглушку ядра — всегда false. Пропуск
                # файла это скрывал. Теперь выбрасываются только строки-заголовки определений.
                txt = "\n".join(
                    ln for ln in txt.splitlines()
                    if not re.match(r"\s*(?:void|bool|int|float|String|uint32_t|size_t)\s+"
                                    r"(?:mc[A-Z]\w*|screenWake)\s*\(", ln))
            called |= {h for h in hooks_in_hdr if re.search(r"\b%s\s*\(" % h, txt)}
        ctx.check("%s: у вызываемых хуков есть переопределение" % sub,
                  called <= strong,
                  "вызывается, но не переопределено: %s — вызов уходит в заглушку"
                  % ", ".join(sorted(called - strong)))

    # Экран, прогресс OTA и батарея — у любой платы. Заглушка здесь означает сломанный
    # интерфейс, а не выключенную функцию, поэтому обе прошивки обязаны их закрыть.
    must = ("mcUiIncoming", "mcUiSensorRx", "mcUiHexScreen", "mcUiSetBrightness",
            "mcUiOtaProgress", "mcUiOtaDone", "mcUiOtaAbort",
            "mcUiOtaSensorProgress", "mcUiOtaSensorAbort",
            "mcBatteryPresent", "mcBatteryPercent", "mcBatteryVoltage")
    for sub in ("meshcore-fork", "tdeck"):
        if not (ctx.tree / sub).is_dir():
            continue  # см. выше: прошивки рядом может не быть вовсе
        strong = set()
        files = _own_sources(ctx, sub)
        for p in files:
            strong |= _hook_defs(p.read_text(encoding="utf-8"))
        ctx.check("%s закрывает все обязательные хуки" % sub,
                  set(must) <= strong,
                  "не переопределены: %s" % ", ".join(sorted(set(must) - strong)))

    if (ctx.tree / "meshcore-fork").is_dir() and (ctx.tree / "tdeck").is_dir():
        print("     сводка: хуков объявлено ядром %d, из них обязательных для обеих прошивок %d; "
              "закрыто форком %d, tdeck — %d"
              % (len(hooks_in_hdr), len(must),
                 len(hooks_in_hdr & _own_hooks(ctx, "meshcore-fork")),
                 len(hooks_in_hdr & _own_hooks(ctx, "tdeck"))))


def _own_hooks(ctx, sub):
    out = set()
    for p in _own_sources(ctx, sub):
        out |= _hook_defs(p.read_text(encoding="utf-8"))
    return out


def _own_sources(ctx, sub):
    """Свои исходники прошивки: и src/, и lib/meshcore/src/.

    Не только `src/`: экран и кнопки у обеих проших прошивок лежат в `lib/meshcore/src/`
    (это их прикладной код, названный так исторически), и первая версия этой проверки смотрела
    только на `src/`. На этом она объявила `screenWake()` незакрытым хуком, хотя он
    переопределён — то есть проверка врала в обе стороны: и ложно ругалась, и пропускала бы
    настоящую пустышку в `lib/`.
    """
    out = []
    for sub_dir in ("src", "lib/meshcore/src"):
        d = ctx.tree / sub / sub_dir
        if d.is_dir():
            out += sorted(d.glob("*.cpp")) + sorted(d.glob("*.c"))
    return out


def _hook_defs(txt):
    """Имена функций-хуков, ОПРЕДЕЛЁННЫХ в тексте (тело с фигурной скобкой).

    Широкий список: и ядро, и прикладной код обеих проших прошивок. Слова `support*` здесь
    ловят и хуки (`supportBusy`), и собственные функции прикладного кода — их полезно знать
    для проверки «вызов есть, а переопределения нет», но НЕЛЬЗЯ считать их хуками ядра: см.
    `_reserved_hooks`.
    """
    return set(re.findall(r"(?m)^\s*(?:void|bool|int|float|String|uint32_t|size_t)\s+"
                          r"((?:mc[A-Z]\w*)|(?:support[A-Z]\w*)|screenWake)\s*\([^;{]*\)\s*\{",
                          txt))


def _sig_mismatch(files, hooks_in_hdr, hdr):
    """Хуки, у которых подпись определения в прошивке разошлась с прототипом в ядре.

    Сравниваются ТИПЫ параметров, а не текст: имена параметров в заголовке и в определении
    различаться могут (в T-Deck `mcBoardPosition` объявлен как `latUdeg/lonUdeg`, а определён
    как `lat/lon`), и это ничего не меняет — имя параметра после компиляции функции не
    различает. Значение по умолчанию в прототипе расхождением тоже не считается: его нельзя
    повторять в определении (ошибка компиляции), так что отсутствие там положено.
    """
    protos = {}
    for name, args in re.findall(
            r"(?m)^\s*(?:void|bool|int|float|String|uint32_t|size_t)\s+(\w+)\s*\(([^;{)]*)\)\s*;",
            hdr):
        protos[name] = _arg_types(args)
    out = set()
    for p in files:
        txt = p.read_text(encoding="utf-8")
        for m in re.finditer(
                r"(?m)^\s*(?:void|bool|int|float|String|uint32_t|size_t)\s+(\w+)\s*\(([^;{)]*)\)\s*\{",
                txt):
            name, args = m.group(1), m.group(2)
            if name not in protos:
                continue
            if _arg_types(args) != protos[name]:
                out.add(name)
    return out


_TYPES = ("void", "bool", "int", "float", "double", "char", "String", "size_t",
          "int8_t", "int16_t", "int32_t", "int64_t", "uint8_t", "uint16_t", "uint32_t",
          "uint64_t", "const")


def _arg_types(args):
    """Типы параметров в каноническом виде: без имён, значений по умолчанию и пробелов."""
    out = []
    for a in args.split(","):
        a = a.split("=")[0].strip()
        # `void` в одиночку — это пустой список параметров, а не параметр типа void.
        if not a or a == "void":
            continue
        # Имя параметра — последний идентификатор, перед которым стоит не ключевое слово.
        # У `const String& text` это `text`, у `int32_t* latUdeg` — `latUdeg`.
        toks = re.findall(r"\w+|[&*]", a)
        name = ""
        for i, t in enumerate(toks):
            if t in _TYPES or t in "&*":
                continue
            name = t
        left = a
        if name:
            left = re.sub(r"\b%s\b" % re.escape(name), "", left, count=1)
        left = re.sub(r"\bconst\b", "", left)
        out.append(re.sub(r"\s+", "", left))
    return tuple(sorted(out))


def _reserved_hooks(files):
    """Из определений прошивки — только те, что ядро имеет право перекрывать.

    Фильтр нужен для одной проверки: «переопределение обязано быть объявлено в
    mc_platform.h». Без него она ругалась бы на прикладные функции `support*`
    (`supportPingTick`, `supportJobTotal` и подобные): ядро их не знает, и заголовком они не
    описываются. Переименуй кто-нибудь прикладную функцию в `mc*` — она тихо переживёт
    появление одноимённого хука в ядре и станет дубликатом символа; поэтому `mc*` и
    `screenWake` в фильтр входят целиком, а не «если есть в заголовке».

    Чего этот фильтр НЕ проверяет и почему это не чинится: шесть хуков ядра живут на префиксе
    `support*` (`supportBusy`, `supportIndexFor`, `supportIndexForAny`, `supportPresent`,
    `supportJobStart`, `supportJobFinished` — `mc_platform.h`, строки 104–117), и прикладной код
    использует тот же префикс. Отличить переопределение хука от собственной функции по имени
    нельзя — единственный признак, что это хук, это наличие его в заголовке, а это ровно то,
    что проверяется. Сузить по нему значит сделать проверку тавтологией: «объявлено в
    заголовке» == «взято из заголовка». Поэтому сверка подписей у `support*` не ловится здесь и
    сделана с другой стороны: каждый хук из заголовка обязан иметь заглушку в ядре, а вызов
    без переопределения ловится проверкой «у вызываемых хуков есть переопределение».
    """
    out = set()
    for p in files:
        txt = p.read_text(encoding="utf-8")
        out |= set(re.findall(r"(?m)^\s*(?:void|bool|int|float|String|uint32_t|size_t)\s+"
                              r"((?:mc[A-Z]\w*)|screenWake)\s*\([^;{]*\)\s*\{", txt))
    return out


def _hook_decls(txt):
    """Имена функций-хуков, ОБЪЯВЛЕННЫХ в тексте (прототип с `;`)."""
    return set(re.findall(r"(?m)^\s*(?:void|bool|int|float|String|uint32_t|size_t)\s+"
                          r"((?:mc[A-Z]\w*)|(?:support[A-Z]\w*)|screenWake)\s*\([^;{]*\)\s*;",
                          txt))


def _weak_hooks(txt):
    out = set()
    for m in re.finditer(r"__attribute__\(\(weak\)\)", txt):
        after = txt[m.end():m.end() + 200]
        mm = re.search(r"(?m)^\s*(?:void|bool|int|float|String|uint32_t|size_t)\s+"
                       r"((?:mc[A-Z]\w*)|(?:support[A-Z]\w*)|screenWake)\s*\(", after)
        if mm:
            out.add(mm.group(1))
    return out


def _own_hook_count(ctx, sub):
    return len(_own_hooks(ctx, sub) & _hook_decls(
        (ctx.core / "include/mc_platform.h").read_text(encoding="utf-8")))


def ota_screen_progress_test(ctx):
    """На экране прошивки видно, сколько пакетов получено из скольких, и он не гаснет.

    Две беды, обе выросли из того, что экранный код писали под быстрый режим.

    Первая — экран. `screenTick()` держит панель зажжённой, пока идёт сессия, и спрашивал про
    это `otaActive`: признак БЫСТРОГО приёма. Медленный режим намеренно не занимает
    `otaPhase`, поэтому на медленной сессии этот признак равен нулю все эти часы, и через две
    минуты панель гасла — ровно тогда, когда на неё и нужно смотреть. Признак прогресса для
    этого и не помогал: он обновляет экран, но не мешает гасить.

    Вторая — сам прогресс. На экране показывался процент и счётчик СЫРЫХ КАДРОВ эфира, то
    есть вместе с повторами. «37%» на часовой сессии не говорит ни о чём, а кадры отвечают
    на другой вопрос. Просили «сколько получено из скольких» — теперь это и написано, и
    единицей приёма выбран чанк: повторы в счётчик не попадают, потому что чанк с неверным
    номером отбрасывается до записи, так что число монотонно и равно «уже у нас на флеше».

    Знаменатель берётся у ядра (`otaSlowRxChunksTotal`), и это не перестраховка: единицу
    приёма знает только ядро, а `otaGot`/`otaTotal` — это БАЙТЫ, а `pkts` — кадры. Спросить
    неоткуда, значит и показать нечего.
    """
    # --- экран не гаснет во время сессии ---
    for sub in ("meshcore-fork", "tdeck"):
        # Прошивки рядом может не быть: CI клонирует одну прошивку рядом с ядром, и второй на
        # диске просто нет. Молчание честнее выдуманного «OK» (см. targets.py). Есть
        # прошивка, но нет в ней экрана — другое дело, об этом сказать надо.
        if not (ctx.tree / sub).is_dir():
            ctx.note("     %s рядом нет — экран не проверяется" % sub)
            continue
        rel = "lib/meshcore/src/display.cpp"
        path = ctx.tree / sub / rel
        if not path.is_file():
            ctx.check("экранный код на месте: %s" % sub, False,
                      "%s есть, а экрана нет: %s" % (sub, str(path)))
            continue
        src = path.read_text(encoding="utf-8")
        tick = ctx.grab(path, "void screenTick(")
        # Именно ВЫЗОВ, а не любое упоминание имени: иначе проверку удовлетворяет комментарий
        # рядом — а комментарий можно написать и вместе с откатом к otaActive, и проверка
        # останется зелёной на неверном коде. (Так и вышло при первом откате.)
        ctx.check("%s: экран не гаснет во время ЛЮБОЙ сессии" % sub,
                  re.search(r"(?m)^[ \t]*if\s*\(\s*otaAnySessionActive\s*\(\s*\)\s*\)"
                            r"[ \t]*\{[ \t]*screenWakeMs", tick) is not None,
                  "screenTick() не спрашивает otaAnySessionActive() в своём теле: медленный "
                  "режим не занимает otaPhase, поэтому otaActive на нём нулевой и панель "
                  "гаснет через две минуты после начала сессии")
        # Предикат живёт в ota.h. Без этого заголовка проверка выше прошла бы на тексте, а
        # сборка упала бы — ровно тот случай, ради которого проверки и пишутся.
        ctx.check("%s: экранный код видит объявление предиката" % sub,
                  '#include "ota.h"' in src,
                  "в %s нет #include \"ota.h\", а screenTick() зовёт otaAnySessionActive() — "
                  "сборка упадёт" % rel)

    # --- «получено из скольких» на экране приёмника ---
    slow_src = (ctx.core / "src/ota_slow.cpp").read_text(encoding="utf-8")
    got_body = ctx.grab(ctx.core / "src/ota_slow.cpp", "uint32_t otaSlowRxChunksGot(")
    total_body = ctx.grab(ctx.core / "src/ota_slow.cpp", "uint32_t otaSlowRxChunksTotal(")
    ctx.check("ядро отдаёт экрану принятые чанки", "slowRxExpect" in got_body,
              "otaSlowRxChunksGot() не берёт slowRxExpect — это единственный счётчик принятых "
              "чанков в приёмнике, и вместо него показывать нечего")
    ctx.check("ядро отдаёт экрану объявленное число чанков", "otaSlowChunks" in total_body,
              "otaSlowRxChunksTotal() не берёт otaSlowChunks — это число чанков из объявления "
              "сессии, то есть единственный знаменатель «из скольких»")
    # Счётчик, который никто не двигает, — тоже «показывает не то»: проверка на откате
    # поймала бы это, но по-человечески видно сразу.
    for name, body in (("otaSlowRxChunksGot", got_body), ("otaSlowRxChunksTotal", total_body)):
        ctx.check("%s() не возвращает константу" % name,
                  not re.search(r"return\s+(0|1)\s*;", body),
                  "%s() возвращает константу: экран будет показывать одно и то же всю "
                  "сессию" % name)

    for sub, rel in (("meshcore-fork", "src/mc_platform.cpp"),
                     ("tdeck", "src/mc_platform.cpp")):
        if not (ctx.tree / sub).is_dir():
            continue  # прошивки рядом нет — см. выше
        path = ctx.tree / sub / rel
        if not path.is_file():
            ctx.check("переопределение хука прогресса на месте: %s" % sub, False,
                      "%s есть, а переопределения нет: %s" % (sub, str(path)))
            continue
        body = ctx.grab(path, "void mcUiOtaSensorProgress(")
        has_both = ("otaSlowRxChunksGot()" in body and "otaSlowRxChunksTotal()" in body)
        ctx.check("%s: экран приёмника печатает «получено из скольких»" % sub, has_both,
                  "mcUiOtaSensorProgress не печатает otaSlowRxChunksGot()/Total(): на экране "
                  "остаётся только процент и счётчик кадров — «37%%» на часовой сессии")
        # Знаменатель обязателен: «получено 812» без «из 2400» — это не ответ на вопрос.
        ctx.check("%s: «из скольких» идёт в том же поле, что и «получено»" % sub,
                  has_both and re.search(r"printf\(\s*\"Pkt\s*%u/%u\"", body) is not None,
                  "в mcUiOtaSensorProgress нет формата вида `Pkt %u/%u`: либо напечатан только "
                  "полученный счётчик, либо разделитель не тот")

    # T-Deck рисует прошивку проект платы, а не общий хук: там своя ячейка, и её надо проверить
    # отдельно, иначе правка пройдёт мимо.
    tdeck_dir = ctx.tree / "tdeck"
    if not tdeck_dir.is_dir():
        ctx.note("     tdeck рядом нет — ячейка RECEIVED не проверяется")
    else:
        ui = (tdeck_dir / "src/tdeck_ui.cpp").read_text(encoding="utf-8")
        draw = (tdeck_dir / "src/tdeck_ui_draw.cpp").read_text(encoding="utf-8")
        ctx.check("tdeck: состояние экрана несёт счётчик пакетов из ядра",
                  re.search(r"otaPktsGot\s*=\s*otaSlowRxChunksGot\s*\(\s*\)\s*;", ui)
                  is not None
                  and re.search(r"otaPktsTotal\s*=\s*otaSlowRxChunksTotal\s*\(\s*\)\s*;", ui)
                  is not None,
                  "tdeck_ui.cpp не заполняет otaPktsGot/otaPktsTotal из ядра — ячейка на панели "
                  "покажет нули всю сессию")
        ctx.check("tdeck: ячейка RECEIVED на медленной сессии показывает пакеты",
                  re.search(r"otaSlow[\s\S]{0,400}PACKETS", draw) is not None
                  and "otaPktsTotal" in draw,
                  "в drawOta нет ветки «медленная сессия → пакеты»: на панели так и останутся "
                  "килобайты, а не «получено N из M»")

    print("     сводка: экран держится на otaAnySessionActive(), счётчик пакетов один на "
          "все три экрана (две прошивки и проект платы T-Deck)")
