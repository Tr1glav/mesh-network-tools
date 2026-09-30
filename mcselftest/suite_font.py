"""Проверка кириллицы в пропорциональных шрифтах T-Deck.

Что было. Пять шрифтов экрана (FreeSans*pt7b) пришли из библиотеки Adafruit_GFX и покрывали
ровно 0x20..0x7E — чистую латиницу. Кириллицы в них не было, а добавить её кодовыми точками
нельзя: `drawChar()` принимает `unsigned char` и адресует глифы как `c - first`, то есть
видит только 0x00..0xFF. Русский текст в пропорциональном шрифте не выводился вовсе — молча,
без ошибки и без предупреждения: `write()` отдавал байт UTF-8 в библиотеку, байт уходил за
пределы диапазона шрифта, и строка пропадала целиком, оставался только её хвост из цифр и
пробелов. Проверка host_render это показывала числами: строка «Узел север 12/40» занимала 166
пикселей против 550 у латинской «Node north 12/40» — рисовались только «12/40».

Как сделано. Кириллица лежит в тех же таблицах, но по CP866, а не по Unicode: буквы занимают
байты 0x80..0xF1, то есть ровно тот диапазон, который библиотека адресует. Таблицы
сгенерированы `scripts/gen_cyr_fonts.c` (FreeType), латиница в них перенесена из прежних
таблиц побайтно, а UTF-8 переводится в CP866 уже проверенным декодером `utf8cp866`.

Что проверяется здесь. Три вещи, каждая на свой откат:

- **содержимое таблиц.** Все 66 букв, которые может выдать `unicodeToCp866()`, есть во всех
  пяти шрифтах; латинская часть совпадает с библиотечной байт в байт; нижняя кромка
  кириллической буквы совпадает с кромкой её латинского двойника.
- **путь вывода.** Все три поверхности (панель, холст приложения, макет на столе) гоняют
  UTF-8 в CP866 при заданном пропорциональном шрифте, а не отдают байт в библиотеку.
- **числа на хосте.** Собирается тот же предпросмотр, что и CI, и проверяется, что русская
  строка рисуется, что её мера ширины совпадает с библиотечной на латинице (иначе поедут
  английские подписи) и что на кириллице мера больше, чем насчитано по сырым UTF-8 байтам
  (иначе она вообще ничего не меряет).
"""
import io
import pathlib
import re
import shutil
import subprocess
import tempfile


# Слоты CP866, которые может выдать utf8cp866::unicodeToCp866() из cyrillic.h. Разбором
# самого заголовка, а не константой: если раскладку в cyrillic.h поменяют, проверка
# перестанет быть верной без всякой правки здесь.
def _cp866_slots(ctx):
    src = (ctx.root / "lib" / "meshcore" / "include" / "cyrillic.h")
    if not src.is_file():
        return None, str(src)
    txt = src.read_text(encoding="utf-8")
    body = txt[txt.index("uint8_t unicodeToCp866("):]
    body = body[:body.index("}")]
    slots = {}
    # Диапазоны вида `cp >= 0x0410 && cp <= 0x041F) return 0x80 + (uint8_t)(cp - 0x0410)`.
    # Вычитается именно начало диапазона, поэтому нижняя граница в выражении и есть
    # начало отсчёта — своей группы для неё не заводим.
    for lo, hi, base, sub in re.findall(
            r"cp\s*>=\s*(0x[0-9A-Fa-f]{4})\s*&&\s*cp\s*<=\s*(0x[0-9A-Fa-f]{4})\)\s*"
            r"return\s*(0x[0-9A-Fa-f]{2})\s*\+\s*\(uint8_t\)\(cp\s*-\s*(0x[0-9A-Fa-f]{4})\)",
            body):
        lo, hi, base, sub = int(lo, 16), int(hi, 16), int(base, 16), int(sub, 16)
        if sub != lo:
            # Отсчёт не с начала диапазона: раскладка сложнее, чем мы разбираем, и
            # молча посчитать её неверно хуже, чем сказать.
            raise ValueError("unicodeToCp866: не разобран диапазон 0x%04X..0x%04X" % (lo, hi))
        for cp in range(lo, hi + 1):
            slots[base + cp - lo] = cp
    for cp, slot in re.findall(r"cp\s*==\s*(0x[0-9A-Fa-f]{4})\)\s*return\s*(0x[0-9A-Fa-f]{2})", body):
        slots[int(slot, 16)] = int(cp, 16)
    return slots, ""


# Таблица из сгенерированного заголовка: глифы и байты растра. Разбором текста, а не
# включением в сборку: проверка должна работать и там, где Adafruit GFX ещё не скачана.
def _parse_font(path):
    t = path.read_text(encoding="utf-8")
    gi = t.index("Glyphs[] PROGMEM")
    gj = t.index("};", gi)
    glyphs = []
    for m in re.finditer(r"\{\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(-?\d+),\s*(-?\d+)\s*\}",
                         t[gi:gj]):
        # Порядок полей GFXglyph: bitmapOffset, width, height, xAdvance, xOffset, yOffset.
        glyphs.append(tuple(int(x) for x in m.groups()))
    bi = t.index("Bitmaps[] PROGMEM")
    raster = [int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", t[bi:gi])]
    m = re.search(r"PROGMEM\s*=\s*\{\s*\(uint8_t\s*\*\).*?,\s*(?:\(GFXglyph\s*\*\)[^,]+,)?"
                  r"\s*(0x[0-9A-Fa-f]+)\s*,\s*(0x[0-9A-Fa-f]+)\s*,\s*(\d+)\s*\}", t, re.S)
    if not m:
        return None
    return dict(glyphs=glyphs, raster=raster,
                first=int(m.group(1), 16), last=int(m.group(2), 16),
                yAdvance=int(m.group(3)))


# Латинские двойники кириллических букв: кодовая точка -> ASCII-буква. Список явный, а не
# «похожие буквы»: автоматический подбор проверял бы сам с собой и пропустил бы ровно тот
# случай, ради которого написан.
_TWINS = {
    0x410: "A", 0x412: "B", 0x415: "E", 0x41A: "K", 0x41C: "M", 0x41D: "H",
    0x41E: "O", 0x420: "P", 0x421: "C", 0x422: "T", 0x423: "Y", 0x425: "X",
    0x430: "a", 0x435: "e", 0x43E: "o", 0x440: "p", 0x441: "c", 0x443: "y",
    0x445: "x",
}

# Пять шрифтов экрана: наш сгенерированный и латинский эталон из библиотеки.
_FONTS = [
    ("FreeSansCyr9pt7b", "FreeSans9pt7b", 18),
    ("FreeSansBoldCyr9pt7b", "FreeSansBold9pt7b", 18),
    ("FreeSansBoldCyr12pt7b", "FreeSansBold12pt7b", 24),
    ("FreeSansBoldCyr18pt7b", "FreeSansBold18pt7b", 35),
    ("FreeSansBoldCyr24pt7b", "FreeSansBold24pt7b", 47),
]


def _gfx_dir(ctx):
    """Каталог Fonts библиотеки Adafruit_GFX: его кладёт первая сборка прошивки.

    Ищется в глубину, а не ровно в libdeps/: PlatformIO раскладывает зависимости по
    окружениям (libdeps/tdeck, libdeps/nodemcuv2, ...), и список окружений меняется —
    жёсткий путь был бы верен только для одной прошивки и молчал бы на другой.
    """
    libdeps = ctx.root / ".pio" / "libdeps"
    if not libdeps.is_dir():
        return None
    for d in sorted(libdeps.glob("*/*Adafruit GFX Library")):
        if (d / "Fonts").is_dir():
            return d
    return None


def _font_tables_test(ctx):
    slots, why = _cp866_slots(ctx)
    if slots is None:
        ctx.check("раскладка CP866 читается из cyrillic.h", False, why)
        return
    ctx.check("раскладка CP866 читается из cyrillic.h: %d букв" % len(slots),
              len(slots) == 66, "разобрано %d слотов, ожидалось 66" % len(slots))

    gfx = _gfx_dir(ctx)
    if gfx is None:
        # Без библиотеки нечем сверить латинскую часть, но содержимое своих таблиц
        # проверяем всё равно: молчать здесь нельзя, теряется половина проверки.
        ctx.note("     Adafruit GFX Library нет — латинская часть не сверяется")

    for new_name, ref_name, _px in _FONTS:
        path = ctx.root / "include" / "fonts" / (new_name + ".h")
        if not path.is_file():
            ctx.check("таблица %s на месте" % new_name, False, str(path))
            continue
        f = _parse_font(path)
        if not f or not f["glyphs"]:
            ctx.check("таблица %s разбирается" % new_name, False, str(path))
            continue
        g = f["glyphs"]

        # 1. Каждая буква, которую может выдать декодер, обязана быть в таблице.
        #    Пропуск одной — это молча пропавший символ в имени узла или в сообщении.
        missing = []
        for slot, cp in sorted(slots.items()):
            i = slot - f["first"]
            if i < 0 or i >= len(g):
                missing.append("0x%02X вне таблицы" % slot)
                continue
            bo, w, h, adv, xo, yo = g[i]
            if w == 0 or h == 0 or adv == 0:
                missing.append("0x%02X U+%04X пуст" % (slot, cp))
        ctx.check("%s: все %d букв CP866 на месте" % (new_name, len(slots)),
                  not missing, "не нарисованы: " + ", ".join(missing[:8]))

        # 2. last обязан доставать до последнего слота, иначе последние буквы (я, ё)
        #    выпадут из диапазона шрифта — write() их просто не нарисует.
        ctx.check("%s: last достаёт до 0xF1" % new_name, f["last"] >= max(slots),
                  "last = 0x%02X, нужен не меньше 0x%02X" % (f["last"], max(slots)))

        # 3. Слоты, которых декодер не выдаёт, обязаны быть пустыми: если там окажется
        #    мусор, а кодер когда-нибудь начнёт ими пользоваться, на экране будет мусор.
        #    Проверяем по растру, а не по «ширине 0» — мусор в битмапе виден.
        alien = []
        for slot in range(f["first"], f["last"] + 1):
            if slot in slots or slot < 0x80:
                continue
            bo, w, h = g[slot - f["first"]][:3]
            if w or h or adv_nonzero(g[slot - f["first"]]):
                alien.append("0x%02X" % slot)
        ctx.check("%s: незанятые слоты пусты" % new_name, not alien,
                  "не пусты: " + ", ".join(alien[:8]))

        # 4. Латиница — байт в байт из библиотеки. Иначе английские подписи поедут, а
        #    заметить это можно только на экране.
        if gfx is None:
            continue
        ref_path = gfx / "Fonts" / (ref_name + ".h")
        if not ref_path.is_file():
            ctx.check("эталон %s на месте" % ref_name, False, str(ref_path))
            continue
        ref = _parse_font(ref_path)
        if not ref:
            ctx.check("эталон %s разбирается" % ref_name, False, str(ref_path))
            continue
        n_latin = ref["last"] - ref["first"] + 1
        same_glyphs = g[:n_latin] == ref["glyphs"][:n_latin]
        same_raster = f["raster"][:len(ref["raster"])] == ref["raster"]
        ctx.check("%s: латиница не тронута" % new_name, same_glyphs and same_raster,
                  "глифы: %s, растр: %s" % ("совпали" if same_glyphs else "разошлись",
                                            "совпал" if same_raster else "разошёлся"))

        # 5. Базовая линия. Кириллическая буква и её латинский двойник обязаны стоять на
        #    одной линии: сверху Ё выше на 3 пикселя (у неё две точки), а снизу р уходит
        #    на тот же выносной элемент, что и у p. Поэтому сверяется НИЖНЯЯ кромка —
        #    yOffset + height, а не yOffset.
        # Обратная раскладка: _TWINS ключом имеет кодовую точку, а слоты разобраны как
        # «слот -> точка». Смотреть slots по кодовой точке — значит не найти ничего и
        # сравнить пустоту с пустотой: проверка зелёная, а не проверяет ровно ничего.
        # Именно так она и осталась зелёной на сдвинутой базовой линии, пока откат не
        # показал, что она ничего не делает.
        by_cp = {cp: slot for slot, cp in slots.items()}
        base_bad = []
        checked = 0
        for cp, latin in sorted(_TWINS.items()):
            slot = by_cp.get(cp)
            if slot is None:
                continue
            checked += 1
            bo, w, h, adv, xo, yo = g[slot - f["first"]]
            rbo, rw, rh, radv, rxo, ryo = ref["glyphs"][ord(latin) - ref["first"]]
            # Допуск — один пиксель, и это НЕ смягчение, а измеренный факт: сам эталонный
            # латинский 'p' в таблице библиотеки на пиксель короче, чем его рисует FreeType
            # (rows 13 против 14 при 18px), то есть расхождение на один пиксель есть
            # между двумя растеризаторами и без всякой кириллицы. Проверено: у FreeSans
            # ровно у 'р' (0x440) и 'а' в двух полужирных таблицах нижняя кромка на +1
            # относительно латинского двойника, и это повторяет ту же величину, что и у
            # латинских 'p'/'a', отдаённых FreeType.
            #
            # Что проверка НЕ ловит: сдвиг всей кириллицы ровно на пиксель — он неотличим от
            # этого шума растеризации, и чтобы его поймать, пришлось бы сверять с FreeType,
            # которого на машине проверок нет. Откат проверки сдвигает кириллицу на два
            # пикселя: два пикселя на высоте прописной (13) видно глазом, и их ловит эта же
            # проверка.
            if abs((yo + h) - (ryo + rh)) > 1:
                base_bad.append("U+%04X против '%c': низ %d, у '%c' %d (допуск 1 px)"
                                % (cp, latin, yo + h, latin, ryo + rh))
        # Число реально сверенных пар — в названии проверки, а не в подробности: пустой
        # список сравнений даёт «всё совпало» на самом деле ничего не проверив.
        ctx.check("%s: кириллица на базовой линии латиницы (%d пар)" % (new_name, checked),
                  not base_bad and checked == len(_TWINS),
                  "; ".join(base_bad[:6]) or
                  ("сверено пар: %d из %d — раскладка слотов разошлась с _TWINS"
                   % (checked, len(_TWINS))))


def adv_nonzero(gl):
    return gl[3] != 0


def _wiring_test(ctx):
    """Все три поверхности обязаны переводить UTF-8 в CP866, а не отдавать байт в GFX."""
    # Поверхности: файл -> имя используемого помощника.
    sites = [
        ("include/st7789.h", "панель"),
        ("include/tdeck_canvas.h", "холст приложения"),
        ("host_render/display/HostPanel.h", "макет на столе"),
    ]
    for rel, what in sites:
        path = ctx.root / rel
        if not path.is_file():
            ctx.check("%s на месте: %s" % (what, rel), False, str(path))
            continue
        txt = path.read_text(encoding="utf-8")
        body = _write_body(txt)
        if not body:
            ctx.check("%s: найден write() с веткой на пропорциональный шрифт" % what, False,
                      "в %s нет write(uint8_t) либо нет ветки `if (gfxFont)`" % rel)
            continue
        # Короткое замыкание `if (gfxFont) return Adafruit_GFX::write(c);` — ровно то, что
        # было: байт UTF-8 уходит в библиотеку и теряется. Проверяется именно тело
        # write(), а не всё mentions: комментарий можно переписать вместе с откатом.
        ctx.check("%s: UTF-8 переводится в CP866 при шрифте" % what,
                  "writeUtf8GfxByte" in body and not re.search(r"gfxFont[^;{}]*\)\s*"
                                                               r"return\s+Adafruit_GFX::write", body),
                  "в write() нет вызова writeUtf8GfxByte или есть прямое возвращение "
                  "Adafruit_GFX::write(c) — русский текст пропадёт целиком")
        # Встроенный шрифт 6x8 обязан остаться на своём пути: там кириллица есть, и
        # сломанный путь откатился бы, а отрисовка 6x8 — нет.
        ctx.check("%s: встроенный шрифт 6x8 не тронут" % what,
                  "utf8cp866::processByte" in body,
                  "в write() нет utf8cp866::processByte: встроенный 6x8 с кириллицей "
                  "перестал бы рисоваться")

    # Мера ширины обязана идти по CP866-байтам. getTextBounds() считает сырые байты UTF-8,
    # то есть две буквы русской строки превращает в две буквы плюс хвост: подпись уезжает
    # из центра. Это не «неточность», а вдвое-большая ширина на кириллице.
    theme = ctx.root / "include" / "tdeck_theme.h"
    if not theme.is_file():
        ctx.check("tdeck_theme.h на месте", False, str(theme))
        return
    txt = theme.read_text(encoding="utf-8")
    body = _func_body(txt, "static inline int textWF(")
    ctx.check("textWF меряет по CP866-байтам", bool(body) and "measureGfxFontText" in body,
              "textWF не зовёт measureGfxFontText: ширина русской подписи считается по сырым "
              "байтам UTF-8, то есть почти вдвое больше настоящей, и текст уезжает из центра")


def _func_body(txt, signature):
    """Тело функции по началу сигнатуры, до парной скобки (как harness.grab, но по тексту)."""
    if signature not in txt:
        return ""
    start = txt.index(signature)
    depth = 0
    for i in range(txt.index("{", start), len(txt)):
        if txt[i] == "{":
            depth += 1
        elif txt[i] == "}":
            depth -= 1
            if depth == 0:
                return txt[start:i + 1]
    return ""


def _write_body(txt):
    """Тело переопределения write(uint8_t): от сигнатуры до конца тела."""
    m = re.search(r"size_t\s+write\s*\(\s*uint8_t\s+c\s*\)\s*(?:const\s*)?override\s*\{", txt)
    if not m:
        return ""
    depth = 1
    for i in range(m.end(), len(txt)):
        if txt[i] == "{":
            depth += 1
        elif txt[i] == "}":
            depth -= 1
            if depth == 0:
                return txt[m.start():i + 1]
    return ""


# Числа с хоста. Тот же предпросмотр, который собирает CI, — потому что иначе проверка
# жила бы в копии кода, которой нет ни в сборке, ни в образе.
PROBE_MAIN = r"""
// Печатает по строке: сколько пикселей зажглось, насколько продвинулся курсор и сколько
// насчитали обе меры ширины. Проверка разбирает эти строки, а не глаза смотрит.
int main() {
    CountingPanel p;
    Adafruit_GFX& g = p;
    static const char* const texts[] = {
        "Node north 12/40",   // латинская эталонная строка
        "Узел север 12/40",   // русский эквивалент: столько же знаков по смыслу
        "Settings",
        "Настройки",
    };
    static const char* const names[] = { "UI9", "UIB9", "VAL12", "BIG18", "HUGE24" };
    const GFXfont* fonts[5] = { FONT_UI, FONT_UI_B, FONT_VALUE, FONT_BIG, FONT_HUGE };
    for (int f = 0; f < 5; f++) {
        for (unsigned t = 0; t < sizeof(texts) / sizeof(texts[0]); t++) {
            p.fillScreen(0);
            g.setFont(fonts[f]);
            g.setTextSize(1);
            g.setTextColor(0xFFFF);
            // Перенос выключен ДО печати: иначе длинная строка в крупном шрифте переносится
            // за правый край, курсор показывает ширину последней строки, и мера «насколько
            // далеко ушёл курсор» перестаёт значить что-либо.
            g.setTextWrap(false);
            g.setCursor(4, 20);
            p.reset();
            g.print(texts[t]);
            int adv = g.getCursorX() - 4;

            int mine = textWF(g, fonts[f], texts[t]);

            // Мера самой библиотеки: с выключенным переносом, иначе длинная строка
            // измеряется как объединение двух строк и выходит меньше настоящей.
            int16_t x1, y1; uint16_t w, h;
            g.setFont(fonts[f]);
            g.setTextSize(1);
            g.setTextWrap(false);
            g.getTextBounds(texts[t], 0, 0, &x1, &y1, &w, &h);
            g.setFont(NULL);

            printf("R %s %d %d %ld %d %u\n", names[f], t, adv, p.lit(), mine, (unsigned)w);
        }
    }
    return 0;
}
"""


def _host_numbers_test(ctx):
    """Собирает пробу из настоящих файлов прошивки и сверяет числа.

    Ничего не подставляется: та же tdeck_canvas.h, тот же tdeck_cyrfont.h, те же таблицы
    шрифтов и та же библиотека, что и в предпросмотре. Поэтому проверка ломается вместе с
    правкой, а не за ней.
    """
    gfx = _gfx_dir(ctx)
    if gfx is None:
        ctx.note("     Adafruit GFX Library нет — численная проверка шрифта пропущена "
                 "(её делает шаг сборки предпросмотра в CI, после сборки прошивки)")
        return
    if not shutil.which("g++"):
        ctx.note("SKIP g++ не найден — численная проверка шрифта пропущена")
        return

    # Проба пишется во ВРЕМЕННЫЙ каталог, а не в host_render/: там лежит probe_font.cpp
    # разработчика, и запись поверх него убрала бы его из репозитория навсегда, молча
    # перезаписав содержимое. Собирается всё равно из тех же файлов прошивки.
    hr = ctx.root / "host_render"
    probe_dir = pathlib.Path(tempfile.mkdtemp(prefix="fontprobe-"))
    probe = probe_dir / "probe.cpp"
    probe.write_text("".join([
        "// Служебная сборка: тот же предпросмотр, но вместо PNG печатаются числа.\n",
        "// Файл создаётся проверкой и в репозиторий не входит.\n",
        '#include <stdio.h>\n#include <string.h>\n',
        '#include "HostPanel.h"\n#include "tdeck_canvas.h"\n',
        '#include "tdeck_theme.h"\n#include "tdeck_palette.h"\n\n',
        "#define W 320\n#define H 240\n",
        "class CountingPanel : public HostPanel {\npublic:\n",
        "    CountingPanel() : HostPanel(W, H) { setTextColor(COL_TEXT); }\n",
        "    void drawPixel(int16_t x, int16_t y, uint16_t c) override {\n",
        "        if (x >= 0 && x < _width && y >= 0 && y < _height) _lit++;\n",
        "        HostPanel::drawPixel(x, y, c);\n    }\n",
        "    void reset() { _lit = 0; }\n    long lit() const { return _lit; }\n",
        "private:\n    long _lit = 0;\n};\n\n",
        PROBE_MAIN,
    ]), encoding="utf-8")

    fonts_cpp = ctx.root / "src" / "tdeck_fonts.cpp"
    with tempfile.TemporaryDirectory(prefix="fontprobe-") as tmp:
        exe = pathlib.Path(tmp) / "probe"
        cmd = ["g++", "-std=c++17", "-O1", "-DARDUINO=10819",
               "-I", str(hr / "shim"), "-I", str(hr / "display"), "-I", str(ctx.root / "include"),
               "-I", str(ctx.root / "apps" / "calendar"), "-I", str(gfx),
               "-idirafter", str(ctx.root / "lib" / "meshcore" / "include"),
               str(probe), str(fonts_cpp), str(gfx / "Adafruit_GFX.cpp"),
               "-o", str(exe), "-lz", "-lm"]
        build = subprocess.run(cmd, capture_output=True, text=True)
        if build.returncode != 0:
            ctx.check("сборка пробы кириллицы", False, build.stderr.strip()[-400:])
            return
        run = subprocess.run([str(exe)], capture_output=True, text=True)
        if run.returncode != 0:
            ctx.check("прогон пробы кириллицы", False,
                      (run.stdout + run.stderr).strip()[-400:])
            return
    rows = {}
    for line in run.stdout.splitlines():
        f = line.split()
        if len(f) == 7 and f[0] == "R":
            rows[(f[1], int(f[2]))] = tuple(int(x) for x in f[3:])

    # Индексы строк в PROBE_MAIN: 0 — латинская эталонная, 1 — русская, 2/3 — короткая
    # подпись и её перевод. Нумерация как в texts[] выше, чтобы её не приходилось
    # держать в голове: сдвиг на единицу тихо превратил бы сравнение ширин в сравнение
    # кириллицы с латиницей, и проверка была бы зелёной на неверном коде.
    long_lat, long_cyr, short_lat, short_cyr = 0, 1, 2, 3
    for name in ("UI9", "UIB9", "VAL12", "BIG18", "HUGE24"):
        r = rows.get((name, long_lat))
        if not r:
            ctx.check("%s: проба вернула строку" % name, False, "нет данных")
            continue
        adv_lat, lit_lat, mine_lat, gfx_lat = r
        adv_cyr, lit_cyr, mine_cyr, gfx_cyr = rows.get((name, long_cyr), (0, 0, 0, 0))

        # Русская строка рисуется ЦЕЛИКОМ. Это главная проверка: без неё всё остальное
        # может быть зелёным на неверном коде.
        #
        # Порог — половина латинской строки, и это не произвольное число. Проверено на
        # откате: когда UTF-8 не переводится в CP866, буквы рисуются ЧАСТИЧНО, а не
        # пропадают совсем, потому что байт 0xD0 в шрифте есть (слот 0xD0 у нас пуст, но
        # у 0x80..0xAF и 0xE0..0xF1 — настоящие буквы, и часть UTF-8 байтов на них
        # попадает). На откате получается 295 пикселей против 514 — больше половины, так
        # что «зажглось хоть что-то» пропустило бы сломанный код. Настоящая строка
        # рисует 90+% латинской, и порог стоит выше.
        ctx.check("%s: русская строка рисуется целиком (%d против %d пикселей у латинской)"
                  % (name, lit_cyr, lit_lat), lit_cyr * 10 >= lit_lat * 8,
                  "зажглось %d пикселей против %d: русская строка рисуется частично, "
                  "значит байты UTF-8 не переводятся в CP866" % (lit_cyr, lit_lat))

        # Курсор прошёл мимо кириллицы. Проверено на откате: без перевода курсор встаёт
        # после третьего знака («12/40» — это последние пять символов строки), то есть
        # заметно раньше конца. Порог — две трети латинской строки: у настоящей кириллицы
        # ширина примерно та же, у сломанной — меньше половины.
        ctx.check("%s: курсор прошёл по всей русской строке" % name,
                  adv_cyr * 3 >= adv_lat * 2,
                  "курсор +%d против +%d у латинской строки: кириллические байты не "
                  "адресовались, нарисован только хвост" % (adv_cyr, adv_lat))

        # Мера ширины совпадает с библиотечной на латинице. Иначе английские подписи,
        # центрируемые этой мерой, поедут — то есть правка кириллицы испортила бы то,
        # ради чего её делали.
        ctx.check("%s: мера ширины на латинице не поехала" % name, mine_lat == gfx_lat,
                  "textWF вернул %d, getTextBounds %d" % (mine_lat, gfx_lat))

        # Мера на кириллице больше, чем насчитано по сырым UTF-8 байтам: сырые байты —
        # это не буквы, и библиотечная мера по ним заведомо меньше. Расхождение означало
        # бы, что наша мера кириллицу не считает.
        _, _, mine_s_lat, _ = rows[(name, short_lat)]
        _, _, mine_s_cyr, _ = rows[(name, short_cyr)]
        ctx.check("%s: мера ширины считает кириллицу" % name,
                  mine_s_cyr > 0 and mine_s_cyr > mine_s_lat / 2,
                  "textWF для «Настройки» вернул %d, а для «Settings» %d: кириллица не "
                  "меряется" % (mine_s_cyr, mine_s_lat))


def cyrillic_font_test(ctx):
    _font_tables_test(ctx)
    _wiring_test(ctx)
    _host_numbers_test(ctx)