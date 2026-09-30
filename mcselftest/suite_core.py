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
#define RELAY_DELAY_MAX_MS 2500
#define MAX_RELAY_HOPS 32
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

    // Транспортные коды (0x00) и direct (route 0x02) не переносятся
    uint8_t tr[256];
    int nt = mkFrame(tr, 0, 0x33);
    tr[0] = (uint8_t)((0x00 << 2) | 0x00);
    want("служебный обмен не ретранслируем", maybeQueueRelay(tr, nt), RELAY_SKIPPED);
    tr[0] = (uint8_t)((0x01 << 2) | 0x02);
    want("direct-кадр не ретранслируем", maybeQueueRelay(tr, nt), RELAY_SKIPPED);

    // Битые кадры: путь объявлен длиннее, чем данных в кадре
    uint8_t bad[256];
    memset(bad, 0, sizeof(bad));
    bad[0] = (uint8_t)((0x01 << 2) | 0x01);
    bad[1] = (uint8_t)(((PATH_HASH_SIZE - 1) << 6) | 5);   // 5 хопов, а данных нет
    want("обрезанный кадр пропущен", maybeQueueRelay(bad, 4), RELAY_SKIPPED);
    want("кадр короче заголовка пропущен", maybeQueueRelay(bad, 1), RELAY_SKIPPED);
    // Путь упёрся в потолок хопов
    bad[1] = (uint8_t)(((PATH_HASH_SIZE - 1) << 6) | 63);
    memset(bad + 2, 0x77, 63 * PATH_HASH_SIZE);
    want("путь длиннее потолка пропущен", maybeQueueRelay(bad, 2 + 63 * PATH_HASH_SIZE + 4),
         RELAY_SKIPPED);

    // Главное, что чинили: забитая очередь обязана отпустить следующую копию.
    // Очередь на 8 слотов уже занята кадрами выше? Нет — занимаем её явно.
    // Очередь уже занята кадрами из предыдущих проверок — освобождаем её целиком, иначе
    // «переполнение» наступит раньше, чем мы его устроим.
    clockMs += 100000;
    meshRelayTick();
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

    # и укладываться в окно сторожа с запасом на эфир
    ack_span = ack_copies * airtime + (ack_copies - 1) * ack_gap
    ctx.check("ackstart укладывается в окно первого чанка",
          ack_gap < flood_min and ack_span < first_chunk,
          "копий %d по %d мс + эфир ≈ %d мс, окно %d мс (пауза флуда %d мс)"
          % (ack_copies, ack_gap, ack_span, first_chunk, flood_min))

    # и бот обязан ждать не меньше, чем сенсор тратит на уход в быстрый канал
    ctx.check("бот ждёт переключения сенсора не меньше, чем сенсор шлёт ackstart",
          settle >= ack_span - airtime,
          "OTA_FAST_SETTLE_MS %d, отправка ackstart ≈ %d мс" % (settle, ack_span))

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
             "PING_REPLY_DELAY_MAX_MS", "FLOOD_REPEATS", "FLOOD_RETRY_MIN_MS"]
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

    # 2. Пауза между копиями обязана быть заметно больше времени в эфире, иначе чужая
    #    передача накрывает все копии сразу и повторы не спасают (было 60 мс при ~500 мс).
    if vals["FLOOD_RETRY_MIN_MS"] < airtime:
        ctx.check("пауза между копиями больше времени в эфире", False,
              "пауза %d мс, кадр в эфире %d мс" % (vals["FLOOD_RETRY_MIN_MS"], airtime))
        return
    ctx.check("пауза между копиями (%d мс) больше времени в эфире (%d мс)"
          % (vals["FLOOD_RETRY_MIN_MS"], airtime), True)

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
            if p.name == "mc_platform.cpp":
                continue
            txt = p.read_text(encoding="utf-8")
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
