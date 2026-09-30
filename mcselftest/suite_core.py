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
    """Сырой кадр быстрого OTA и разбор meshcore-кадра — разные ветви, и это не стиль,
    а работоспособность прошивки по быстрому каналу.

    Было `if (быстрый кадр) {...} else if (checkAndMarkSeen(...)) {...} else {...}`: цепочка
    дедупа и разбора пропускалась для сырого кадра. При переносе ретрансляции выше дедупа
    цепочка осталась снаружи `else` и стала общей: каждый принятый кусок образа проходил
    checkAndMarkSeen (он попадал в общий кольцевой буфер дедупа) и parseMeshCorePacket, а
    в конце звался radio.startReceive() — в том числе поверх ещё не ушедшего в эфир WACK.
    Приёмник переподписывался, не дождавшись конца собственной передачи, сенсор переставал
    подтверждать пачки, а бот уходил в otaBotAbort("no progress") и возвращал обычный
    конфиг радио. Симптом на железе: «отправитель не дожидается и переключается обратно».

    Проверяем структурно: обе ветви обязаны быть альтернативами одного `if`, то есть
    дедуп не может лежать на глубине тела «быстрой» ветви и не может идти после неё
    отдельным оператором."""
    body = ctx.span(ctx.core / "src/radio_rx.cpp", "void radioRxTick()", "\n}\n")
    # комментарии выкидываем: в них и braces, и слова «else» встречаются свободно
    lines = []
    for raw in body.split("\n"):
        i = raw.find("//")
        lines.append((raw if i < 0 else raw[:i]).strip())
    lines = [ln for ln in lines if ln]

    # Глубина скобок ПЕРЕД каждой строкой: у «} else {» она на уровень больше тела
    # ветви, поэтому именно так и узнаётся else того самого if.
    depths = []
    d = 0
    for ln in lines:
        depths.append(d)
        d += ln.count("{") - ln.count("}")

    def find(pred):
        for i, ln in enumerate(lines):
            if pred(ln):
                return i
        return -1

    # условие занимает две строки, поэтому ищем по «pktLen >= 9 && otaFastMode»
    cond_at = find(lambda ln: "pktLen >= 9 && otaFastMode" in ln)
    dedup_at = find(lambda ln: ln.startswith("if (checkAndMarkSeen("))
    if cond_at < 0 or dedup_at < 0:
        ctx.check("сырой кадр быстрого OTA не попадает в дедуп и разбор meshcore", False,
              "не нашли ветку быстрого кадра или checkAndMarkSeen в radioRxTick")
        return

    # Дедуп обязан лежать ВНУТРИ else-тела «быстрого» кадра: на уровень глубже самого if
    # и после закрывающей `} else {`. Когда цепочка дедупа стояла рядом с else отдельным
    # оператором, глубина была та же — и код выполнялся для сырых кадров тоже.
    D = depths[cond_at]
    ok = depths[dedup_at] == D + 1
    detail = ""
    if not ok:
        detail = ("дедуп на глубине %d, а тело else-ветки на %d: цепочка дедупа выпала "
                  "из else и достаёт сырые кадры" % (depths[dedup_at], D + 1))
    else:
        has_else = any(lines[i].startswith("} else {") and depths[i] == D + 1
                       for i in range(cond_at + 1, dedup_at))
        if not has_else:
            ok, detail = False, "между быстрым кадром и дедупом нет else того же if"
    ctx.check("сырой кадр быстрого OTA не попадает в дедуп и разбор meshcore", ok, detail)


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
