"""Проверки прошивки meshcore-fork (Heltec V3 / V4.3).

Только то, что принадлежит самому форку: страница координатора (разметка в web.cpp против
скрипта в web/app.js против маршрутов сервера и полей /info), совместимость кнопок в MQTT,
границы команд телефонного приложения. Проверки ядра — в suite_core.
"""
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

from .cshims import STRING_PRELUDE


BUTTON_MAIN = r"""
static int fails = 0;
static void expect(bool ok, const char* what) {
    if (!ok) { printf("не сошлось: %s\n", what); fails++; }
}
static void expectEq(const char* got, const char* want, const char* what) {
    if (strcmp(got, want) != 0) {
        printf("%s: получено \"%s\", ожидалось \"%s\"\n", what, got, want);
        fails++;
    }
}

int main() {
    // Ровно то сообщение, как его видит сеть после устранения дублей.
    expectEq(SENSOR_MSG_BUTTON, "button", "основа кнопки");
    expectEq(SENSOR_MSG_BUTTON2, "button2", "основа второй кнопки");

    String bare;
    // Без номера отправки — совместимость не должна ломаться и на старых узлах
    expect(bareButton("button", bare) && bare == "button", "button без номера");
    expect(bareButton("button2", bare) && bare == "button2", "button2 без номера");
    // С номером: наружу уходит прежнее значение, иначе сломались бы все автоматизации
    expect(bareButton("button:1", bare) && bare == "button", "button:1");
    expect(bareButton("button:42", bare) && bare == "button", "button:42");
    expect(bareButton("button2:7", bare) && bare == "button2", "button2:7");
    // Границы: нулевой номер, длинный номер, номер из одного знака
    expect(bareButton("button:0", bare) && bare == "button", "button:0");
    expect(bareButton("button:999999999", bare) && bare == "button", "длинный номер");

    // Главное: чужие сообщения не должны превращаться в нажатие. У сенсоров «t:25» —
    // самый обычный текст, и молча срезать у него хвост значит подделать событие кнопки
    // в Home Assistant: автоматизация сработает на датчике температуры.
    const char* notButtons[] = {
        "t:25", "t", "button:abc", "button:", "button:x1", "button2:", "button2:1a",
        "button:1x", "button:-1", "button: 1", "button:1 ", "Button:1", "BUTTON2:3",
        "xbutton:1", "button3:1", "кнопка:1", "", "cfg:ok:save", "ota:done", "t:1:2"
    };
    for (unsigned i = 0; i < sizeof(notButtons) / sizeof(notButtons[0]); i++) {
        if (bareButton(notButtons[i], bare)) {
            printf("принято за кнопку: \"%s\" -> \"%s\"\n", notButtons[i], bare.c_str());
            fails++;
        }
    }
    if (fails) { printf("не сошлось: %d\n", fails); return 1; }
    printf("ok\n");
    return 0;
}
"""


def button_compat_test(ctx):
    """Совместимость кнопок в MQTT.

    Сенсор шлёт «button:N» — номер нужен, чтобы два одинаковых нажатия в одну секунду не
    выглядели дублем в сети. Наружу, в MQTT и Home Assistant, этот номер выходить не должен:
    иначе у всех автоматизаций, подписанных на «button», значение события поменяется. Урезать
    надо строго «основа + двоеточие + цифры», иначе под нож попадут обычные данные узла
    («t:25») и в HA начнут приходить ложные нажатия."""
    if not shutil.which("g++"):
        print("SKIP g++ не найден — совместимость кнопок не проверена")
        return
    cfg = (ctx.core / "include" / "config.h").read_text(encoding="utf-8")
    defs = []
    for n in ("SENSOR_MSG_BUTTON", "SENSOR_MSG_BUTTON2"):
        m = re.search(r"^#define\s+" + n + r'\s+"([^"]*)"', cfg, re.M)
        if not m:
            ctx.check("совместимость кнопок: %s определён" % n, False)
            return
        defs.append("#define %s \"%s\"" % (n, m.group(1)))
    code = (STRING_PRELUDE + "\n".join(defs) + "\n"
            + ctx.grab("lib/meshcore/src/mqtt.cpp", "static bool bareButton(") + "\n"
            + BUTTON_MAIN)
    exe, build = ctx.host_build(code, "b.cpp")
    if exe is None:
        ctx.check("сборка теста совместимости кнопок", False, build[:400])
        return
    run = subprocess.run([str(exe)], capture_output=True, text=True)
    ctx.check("кнопки в MQTT: номер отправки срезается, чужие сообщения не трогаются",
          run.returncode == 0, (run.stdout + run.stderr).strip()[:600])
    # Отдельно: в MQTT наружу уходит именно оголённое значение, а при неудаче — исходное.
    # Это одна строка, и ошибка в ней тихо ломает все автоматизации разом.
    mq = (ctx.root / "lib/meshcore/src/mqtt.cpp").read_text(encoding="utf-8")
    ctx.check("в MQTT наружу уходит оголённое значение кнопки",
          "isBtn ? btnMsg.c_str() : lastMessage.c_str()" in mq)


def page_js_test(ctx):
    js = (ctx.root / "web/app.js").read_text(encoding="utf-8")
    ctx.check("JavaScript страницы непустой", len(js) > 1000)
    if not shutil.which("node"):
        print("SKIP node не найден — синтаксис страницы не проверен")
        return
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp) / "page.js"
        path.write_text(js, encoding="utf-8")
        run = subprocess.run(["node", "--check", str(path)], capture_output=True, text=True)
        ctx.check("синтаксис JavaScript страницы", run.returncode == 0, run.stderr.strip()[:400])
    page_ids_test(ctx, js)


def page_ids_test(ctx, js):
    """Разметка и скрипт страницы лежат в разных файлах, и страница приходит с устройства,
    где починить разъехавшуюся пару нечем: страница просто молча не работает. Здесь ловим
    это на сборке. HTML берём из web.cpp — он и есть источник страницы, отдельного файла
    с разметкой нет."""
    web_cpp = (ctx.root / "lib/meshcore/src/web.cpp").read_text(encoding="utf-8")
    html_ids = set(re.findall(r"id='([A-Za-z][\w-]*)'", web_cpp))
    # Идентификаторы, которые скрипт ищет через $('имя'), плюс обращения строкой в коде
    # ($("имя") тоже встречается после переписывания). Отдельно — id, которые скрипт сам
    # ставит элементу (кнопка сохранённой прошивки): их в разметке нет по определению.
    js_ids = set(re.findall(r"\$\(\s*['\"]([A-Za-z][\w-]*)['\"]\s*\)", js))
    js_ids -= set(re.findall(r"\.id\s*=\s*['\"]([A-Za-z][\w-]*)['\"]", js))
    missing = sorted(js_ids - html_ids)
    ctx.check("все элементы страницы, которые ищет скрипт, есть в разметке",
          not missing, "нет в разметке: " + ", ".join(missing))
    # Обратная сторона: id в разметке, к которому скрипт не обращается, — опечатка или
    # осиротевший кусок после переделки страницы. Панели вкладок открываются по data-tab,
    # а не по id, поэтому их имена из проверки убираем.
    unused = sorted(i for i in html_ids - js_ids if not i.startswith("p-"))
    ctx.check("в разметке нет неиспользуемых элементов", not unused,
          "скрипт не обращается: " + ", ".join(unused))
    # Вкладки: у каждой кнопки data-tab должна быть панель с таким же id, и наоборот.
    tabs = set(re.findall(r"data-tab='([\w-]+)'", web_cpp))
    panels = set(re.findall(r"class='panel[^']*' id='p-([\w-]+)'", web_cpp))
    ctx.check("у каждой вкладки есть панель и наоборот", tabs == panels,
          "вкладки: %s, панели: %s" % (sorted(tabs), sorted(panels)))
    # Имя панели собирается в скрипте как 'p-'+имя вкладки, а не выписывается по списку.
    ctx.check("скрипт открывает панели по data-tab", "'p-'+b.dataset.tab" in js)
    # Разметка лежит строкой в C++, и браузер чинит её молча: незакрытый div не ломает
    # страницу, а просто прячет под собой половину. Считаем пары тегов с содержимым.
    html = html_body(web_cpp)
    ctx.check("разметка страницы найдена в web.cpp", html is not None)
    if html:
        for tag in ("div", "section", "span", "button", "label", "details", "pre"):
            opened = len(re.findall(r"<%s\b" % tag, html))
            closed = html.count("</%s>" % tag)
            ctx.check("теги <%s> закрыты (%d/%d)" % (tag, opened, closed), opened == closed)
        # Теги без содержимого (HTML5) закрывать не нужно, но потерянная скобка после
        # одного из них делает разметку неразборчивой: <input ...><div> — и дальше всё
        # едет. Считаем теги, у которых скобка на месте, и сравниваем с общим числом.
        for tag in ("meta", "link", "input"):
            closed = len(re.findall(r"<%s\b[^<>]*>" % tag, html))
            total = len(re.findall(r"<%s\b" % tag, html))
            ctx.check("одиночные теги <%s> не разъехались (%d)" % (tag, closed), closed == total,
                  "потеряна скобка: %d из %d" % (closed, total))
    endpoints_test(ctx, js, web_cpp, html or "")
    info_fields_test(ctx, js, web_cpp)


def html_body(web_cpp):
    """Разметка страницы из web.cpp: она лежит там строковым литералом, отдельного файла
    с разметкой нет, а искать её в C++ пришлось бы руками."""
    m = re.search(r"R\"HTML\((.*?)\)HTML\"", web_cpp, re.S)
    return m.group(1) if m else None


def endpoints_test(ctx, js, web_cpp, html):
    """Каждый адрес, который зовёт страница, обязан обслуживаться сервером.

    Скрипт и сервер лежат в разных файлах, и разъехавшаяся пара на устройстве выглядит
    так: страница загрузилась, кнопка нажата, ответа нет, в консоли 404. Ловим на сборке."""
    served = set(re.findall(r"otaServer\.on\(\s*\"([^\"?]+)\"", web_cpp))
    ctx.check("маршруты сервера найдены", bool(served),
          "в web.cpp нет ни одного otaServer.on(...)")
    called = set()
    for url in re.findall(r"fetch\(\s*'([^']+)'", js):
        called.add(url.split("?")[0].split("#")[0])
    # Ссылки и скрипты из разметки — тоже адреса, которые сервер обязан отдавать.
    for href in re.findall(r"(?:href|src)='(/[^'?]*)", html):
        called.add(href)
    missing = sorted(u for u in called if u and u not in served)
    ctx.check("все адреса страницы обслуживает сервер", not missing,
          "нет маршрута: " + ", ".join(missing))
    # Страница, стилевые файлы и скрипт должны отдаваться корнем: без них не грузится
    # ничего, а проверка выше этого не отлавливает — адреса в разметке есть.
    for need in ("/", "/style.css", "/app.js"):
        ctx.check("сервер отдаёт %s" % need, need in served)
    # Обращения из скрипта: их не должно быть больше, чем маршрутов, иначе страница
    # зовёт то, что сервер забыл (список выше это уже ловит) — проверяем, что скрипт не
    # остался с адресом, который сервер когда-то отдавал вручную мимо otaServer.on.
    manual = set(re.findall(r"(?:server|otaServer)\.onNotFound", web_cpp))
    ctx.check("у сервера нет адресов вне otaServer.on", not manual,
          "есть onNotFound: такие адреса проверка выше не видит")


def info_fields_test(ctx, js, web_cpp):
    """Поля, которые страница читает из /info, обязаны быть в ответе.

    Ответ собирается вручную строковыми кусками, и забытое поле даёт не ошибку сборки,
    а тихое «неизвестно» в интерфейсе: счётчик потерь, например, просто не виден."""
    # info.<поле> в скрипте
    used = set(re.findall(r"\binfo\.([A-Za-z_]\w*)", js))
    # Ответ /info: собирается в web.cpp, поэтому ищем имена полей в его теле
    # Тело обработчика, а не строка его регистрации: иначе под проверку попадает пустое
    # место, и проверка «проходит», ничего не проверяя.
    handler = re.search(r"void\s+otaHandleInfo\s*\([^)]*\)\s*\{(.*?)\n\}", web_cpp, re.S)
    ctx.check("обработчик /info найден", handler is not None)
    if not handler:
        return
    body = handler.group(1)

    def field(name):
        """Имя поля в ответе /info. JSON собирается строковым литералом, поэтому в исходнике
        ключ выглядит как \\"имя\\", а не "имя" — ищем оба написания."""
        return re.search(r'\\?"' + re.escape(name) + r'\\?"', body) is not None

    missing = sorted(f for f in used if not field(f))
    ctx.check("все поля, которые читает страница, есть в /info", not missing,
          "нет в ответе: " + ", ".join(missing))
    # Обратная сторона: счётчики потерь обязаны попадать и в /info, и в страницу —
    # иначе диагностика собрана, но никто её не видит.
    for name in ("cadg", "rlq", "rdr", "rdf", "dmn"):
        ctx.check("счётчик потерь %s отдаётся в /info" % name, field(name))
        ctx.check("счётчик потерь %s показывается страницей" % name, name in js)


COMPANION_PRELUDE = (
    "#include <cstdint>\n#include <cstdio>\n#include <cstring>\n#include <cstddef>\n"
    "#define MAX_FRAME_SIZE 240\n"
)


COMPANION_MAIN = r"""
int main() {
    // advertPathBytes: байт длины приезжает из NVS, то есть мог достаться от другой версии
    // прошивки. Проверяем все 256 значений против вместимости буфера пути.
    for (int v = 0; v < 256; v++) {
        uint16_t b = advertPathBytes((uint8_t)v, 64);
        if (b > 64) { printf("advertPathBytes: %u байт при advPathLen=%d\n", b, v); return 1; }
        // разумные значения не должны теряться: 0 хопов, 1 хоп с 1-байтовым хэшем
        if (v == 0x00 && b != 0) { printf("advertPathBytes: 0 хопов дало %u\n", b); return 1; }
        if (v == 0x01 && b != 1) { printf("advertPathBytes: 1 хоп 1 байт дало %u\n", b); return 1; }
        if (v == 0x41 && b != 2) { printf("advertPathBytes: 1 хоп 2 байта дало %u\n", b); return 1; }
    }
    // 63 хопа по 2 байта = 126 байт: в буфер 64 не влезает, отдаём пустой путь.
    // Разряд хэша лежит в бите 6, поэтому двухбайтовый хэш — это 0x40 и выше.
    if (advertPathBytes(0x7F, 64) != 0) { printf("advertPathBytes: не влезает, но не отброшено\n"); return 1; }
    if (advertPathBytes(0x61, 64) != 0) { printf("advertPathBytes: 33 хопа по 2 байта не отброшены\n"); return 1; }
    // ровно во вместимость: 32 хопа по 2 байта = 64 — пропускаем
    if (advertPathBytes(0x60, 64) != 64) { printf("advertPathBytes: ровно 64 байта отброшены\n"); return 1; }
    if (advertPathBytes(0x3F, 64) != 63) { printf("advertPathBytes: 63 хопа по 1 байту\n"); return 1; }

    // putTextBounded: текст из очереди не должен вылезти за предел кадра при любой
    // уже набранной длине и любой длине текста.
    uint8_t frame[512];
    for (int used = 0; used <= 300; used++) {
        for (int tl = 0; tl <= 400; tl++) {
            char text[401];
            memset(text, 'T', sizeof(text));
            memset(frame, 0, sizeof(frame));
            size_t got = putTextBounded(frame, (size_t)used, MAX_FRAME_SIZE, text, (size_t)tl);
            if (got > MAX_FRAME_SIZE) {
                printf("putTextBounded: длина %u при used=%d tl=%d\n", (unsigned)got, used, tl);
                return 1;
            }
            // сколько байт обязано было вписаться: столько, сколько влезает после used
            size_t copied = 0;
            if ((size_t)used < MAX_FRAME_SIZE) {
                size_t room = MAX_FRAME_SIZE - (size_t)used;
                copied = ((size_t)tl < room) ? (size_t)tl : room;
            }
            for (size_t k = 0; k < copied; k++) {
                if (frame[used + k] != 'T') { printf("putTextBounded: байт %u не записан\n", (unsigned)k); return 1; }
            }
            for (size_t k = used + copied; k < MAX_FRAME_SIZE; k++) {
                if (frame[k] != 0) { printf("putTextBounded: записано за пределом текста\n"); return 1; }
            }
        }
    }
    // предел превышен уже начатком кадра — вписать нельзя ничего, но и выйти нельзя
    if (putTextBounded(frame, MAX_FRAME_SIZE + 10, MAX_FRAME_SIZE, "x", 1) != MAX_FRAME_SIZE) {
        printf("putTextBounded: used больше предела\n"); return 1;
    }
    return 0;
}
"""


def advert_path_prefix_test(ctx):
    """Путь до узла отдаётся по НАЧАЛУ ключа, а не только по полным 32 байтам.

    Из-за этого приложение не показывало маршрут ни для одного узла, слышанного через нашу
    прошивку, — при том что узлы с однобайтовым и двухбайтовым хэшем хопа рядом маршрут
    показывали. Размер хэша был тут не при чём.

    Приложение спрашивает путь командой 42 по НАЧАЛУ публичного ключа: у хопа в маршруте
    полного ключа у него нет и быть не может — в пути передаются хэши ретрансляторов, а не
    ключи. Обработчик требовал `len >= 2 + 32` и сравнивал все 32 байта, поэтому любой такой
    запрос получал «не найдено». Оригинал держит для этого отдельную таблицу, ключуемую семью
    байтами (`AdvertPath::pubkey_prefix[7]`), и отвечает.

    Рядом, в запросе контакта по ключу, префикс обрабатывался правильно с самого начала — то
    есть про это поведение приложения прошивка знала, просто не применяла в соседнем месте.
    Поэтому проверка требует ОДНОГО поиска на оба запроса."""
    proto = ctx.root / "lib" / "meshcore" / "src" / "companion_proto.cpp"
    comp = ctx.root / "lib" / "meshcore" / "src" / "companion.cpp"
    hdr = ctx.root / "lib" / "meshcore" / "include" / "companion_internal.h"
    if not (proto.is_file() and comp.is_file() and hdr.is_file()):
        ctx.note("     SKIP advert_path_prefix_test: кода компаньона рядом нет")
        return
    ptxt, ctxt, htxt = (f.read_text(encoding="utf-8") for f in (proto, comp, hdr))

    ctx.check("поиск по префиксу ключа существует", "int contactFindPrefix(" in ctxt,
              "нет contactFindPrefix: искать узел по началу ключа нечем")
    ctx.check("минимальная длина префикса объявлена", "CONTACT_KEY_PREFIX_MIN" in htxt,
              "нет предела снизу: короткий префикс совпадёт с чужим узлом")

    # Оба запроса обязаны ходить через один поиск: расхождение между ними и было причиной.
    body = ptxt[ptxt.find("case CMD_GET_ADVERT_PATH"):]
    body = body[:body.find("case CMD_SET_CHANNEL")] if "case CMD_SET_CHANNEL" in body else body
    code = "\n".join((ln if ln.find("//") < 0 else ln[:ln.find("//")])
                      for ln in body.splitlines())
    ctx.check("запрос пути ищет по префиксу", "contactFindPrefix(" in code,
              "обработчик команды 42 снова требует полный ключ — приложение останется без "
              "маршрута для каждого хопа")
    ctx.check("запрос пути не требует все 32 байта", "len >= 2 + 32" not in code,
              "в обработчике остался порог на полный ключ: запрос с префиксом будет отвергнут")
    ctx.check("запрос контакта ищет тем же поиском",
              code.count("contactFindPrefix(") >= 2,
              "запрос контакта по ключу ищет своим способом — расхождение между двумя "
              "соседними запросами и было причиной поломки")

    # Предел снизу обязан пропускать то, что приложение РЕАЛЬНО присылает. Сколько именно —
    # видно в обработчике личного сообщения: там адрес берётся фиксированным числом байтов.
    # Сначала здесь стояло «не меньше семи» по ширине таблицы оригинала, и это была
    # регрессия: семь описывают, сколько оригинал ХРАНИТ, а приложение присылает шесть, и
    # запрос контакта по ключу начал отвечать «не найдено». Поэтому проверка сверяет порог не
    # с числом из чужого кода, а с числом из нашего же обработчика.
    m = re.search(r"#define\s+CONTACT_KEY_PREFIX_MIN\s+(\d+)", htxt)
    # Обработчик личного сообщения лежит ниже разобранного куска, поэтому смотрим весь файл.
    full = "\n".join((ln if ln.find("//") < 0 else ln[:ln.find("//")])
                      for ln in ptxt.splitlines())
    used = re.search(r"contactFindPrefix\(&f\[7\],\s*(\d+)\)", full)
    ctx.check("порог префикса пропускает то, что присылает приложение",
              m is not None and used is not None and int(m.group(1)) <= int(used.group(1)),
              "порог %s, а личное сообщение адресуется %s байтами: такой запрос получит "
              "«не найдено»" % (m.group(1) if m else "нет", used.group(1) if used else "?"))
    ctx.check("порог префикса не вырожден (>= 4 байт)",
              m is not None and int(m.group(1)) >= 4,
              "CONTACT_KEY_PREFIX_MIN = %s: по такому началу ключа ответ уйдёт про чужой узел"
              % (m.group(1) if m else "нет"))
    ctx.check("личное сообщение ищет контакт тем же поиском",
              "contactFindPrefix(&f[7]" in full,
              "обработчик личного сообщения ищет контакт своим способом — именно расхождение "
              "соседних мест дважды за день и приводило к поломке")


def ack_confirm_test(ctx):
    """Отправленное личное сообщение получает галочку «доставлено».

    Вторая половина подтверждения доставки: ядро умеет отправить ACK и принять чужой, но
    сверить пришедшее может только тот, кто отправлял, — а отправляет приложение через
    компаньона. Без этой половины подтверждение приходит и уходит в никуда, и сообщение у
    приложения навсегда остаётся без галочки.

    Хэш считает ЯДРО при сборке кадра (`buildPrivateTextFrame` с `expectedAck4`), а не
    компаньон: он выводится из того же открытого текста, который собирается внутри, и
    посчитанный снаружи разойдётся с кадром при первой правке раскладки."""
    comp = ctx.root / "lib" / "meshcore" / "src" / "companion.cpp"
    proto = ctx.root / "lib" / "meshcore" / "src" / "companion_proto.cpp"
    hdr = ctx.root / "lib" / "meshcore" / "include" / "companion_internal.h"
    if not (comp.is_file() and proto.is_file() and hdr.is_file()):
        ctx.note("     SKIP ack_confirm_test: кода компаньона рядом нет")
        return
    ctxt, ptxt, htxt = (f.read_text(encoding="utf-8") for f in (comp, proto, hdr))

    ctx.check("компаньон переопределяет хук подтверждения",
              re.search(r"(?m)^void\s+mcOnAckRecv\s*\(", ctxt) is not None,
              "mcOnAckRecv не переопределён: сработает заглушка ядра, и подтверждение "
              "приложению не дойдёт")
    ctx.check("приложению уходит код «доставлено»",
              "PUSH_CODE_SEND_CONFIRMED" in htxt and "PUSH_CODE_SEND_CONFIRMED" in ctxt,
              "нет пуша о доставке: ядро приняло подтверждение, а приложение о нём не узнает")
    ctx.check("в пуше есть время в пути",
              re.search(r"trip", ctxt) is not None,
              "приложению отдаётся только факт: оригинал присылает ещё и время в пути, и "
              "приложение его показывает")

    # Хэш обязан приходить ИЗ ЯДРА вместе с кадром, а не считаться здесь заново.
    ctx.check("ожидаемый хэш берётся у сборщика кадра",
              re.search(r"buildPrivateTextFrame\([^;]*expAck\s*\)", ptxt) is not None
              and "ackExpect(" in ptxt,
              "компаньон не запоминает ожидаемый хэш при отправке: сверять пришедшее "
              "подтверждение будет не с чем")
    ctx.check("хэш не пересчитывается в компаньоне",
              "sha256Trunc(" not in ctxt and "sha256Trunc(" not in ptxt,
              "компаньон считает хэш сам: он выводится из открытого текста, который собирает "
              "ядро, и две копии расчёта разъедутся молча")

    # Повторное подтверждение не должно давать второй пуш: копии флуда приходят по нескольку.
    ack_fn = ctxt[ctxt.find("void mcOnAckRecv("):]
    ack_fn = ack_fn[:ack_fn.find("\n}\n") + 3] if "\n}\n" in ack_fn else ack_fn
    ctx.check("слот освобождается на первом совпадении",
              re.search(r"used\s*=\s*false", ack_fn) is not None,
              "подтверждение приходит копиями, и без освобождения слота приложение получит "
              "несколько пушей об одном сообщении")


def companion_send_latency_test(ctx):
    """Ответ приложению не ждёт эфира.

    Владелец: «на компаньоне приложение при отправке сообщения как будто притормаживает, на
    официальном такого нет». Причина была в порядке двух действий: обработчик команды сначала
    выходил в эфир (`floodSend` — ожидание тишины в канале до 1.5 с плюс время кадра), и
    только потом отвечал приложению. Приложение ждёт это подтверждение, чтобы показать
    сообщение отправленным, — вот и «притормаживает».

    У оригинала этого нет потому, что там передача асинхронная целиком: пакет кладётся в
    очередь диспетчера, ответ уходит немедленно, эфиром занимается диспетчер. У нас передача
    блокирующая, но ответ от неё отвязан: обе команды отправки кладут ВСЕ копии в очередь
    (`floodSendQueued`) и отвечают сразу, а первая копия уходит с ближайшего `meshTxTick()`.

    Проверка держит именно порядок: в обработчиках команд приложения не должно остаться
    отправки, которая выходит в эфир до ответа."""
    proto = ctx.root / "lib" / "meshcore" / "src" / "companion_proto.cpp"
    if not proto.is_file():
        ctx.note("     SKIP companion_send_latency_test: кода компаньона рядом нет")
        return
    txt = proto.read_text(encoding="utf-8")
    code = "\n".join((ln if ln.find("//") < 0 else ln[:ln.find("//")])
                      for ln in txt.splitlines())
    # Блокирующая отправка в обработчике команды — это и есть задержка ответа.
    blocking = re.findall(r"(?<!Queued)\bfloodSend\s*\(", code)
    ctx.check("обработчики приложения не выходят в эфир до ответа", not blocking,
              "в companion_proto.cpp осталось %d вызов(а) floodSend: ответ приложению "
              "задержится на ожидание канала и время кадра" % len(blocking))
    ctx.check("отправка из приложения идёт через очередь",
              "floodSendQueued(" in code,
              "ни одной отправки через floodSendQueued: сообщение уходит в эфир из "
              "обработчика команды, и подтверждение опаздывает")
    # И сама очередь обязана существовать в ядре, иначе «queued» ничего не значит.
    core_tx = (ctx.core / "src" / "mesh_tx.cpp").read_text(encoding="utf-8")
    ctx.check("ядро умеет отправку без выхода в эфир",
              "void floodSendQueued(" in core_tx,
              "в ядре нет floodSendQueued — очереди для первой копии не существует")


def companion_bounds_test(ctx):
    if not shutil.which("g++"):
        print("SKIP g++ не найден — границы команд приложения не проверены")
        return
    code = (
        COMPANION_PRELUDE
        + ctx.grab("lib/meshcore/src/companion_proto.cpp", "static uint16_t advertPathBytes(") + "\n"
        + ctx.grab("lib/meshcore/src/companion_proto.cpp", "static size_t putTextBounded(") + "\n"
        + COMPANION_MAIN
    )
    with tempfile.TemporaryDirectory() as tmp:
        src = pathlib.Path(tmp) / "c.cpp"
        exe = pathlib.Path(tmp) / "c"
        src.write_text(code, encoding="utf-8")
        build = subprocess.run(
            ["g++", "-std=c++17", "-fsanitize=address,undefined", "-g", str(src), "-o", str(exe)],
            capture_output=True, text=True)
        if build.returncode != 0:
            ctx.check("сборка теста границ команд приложения", False, build.stderr.strip()[:400])
            return
        run = subprocess.run([str(exe)], capture_output=True, text=True)
        ctx.check("границы команд приложения (путь рекламы, текст в кадре)",
              run.returncode == 0, (run.stdout + run.stderr).strip()[:600])


# ===== Добавка к общей проверке чистых функций =====
# Эти две функции принадлежат форку (fwupdate.cpp и mqtt.cpp), но проверяются в той же
# хостовой сборке, что и чистые функции ядра: заводить ради них вторую сборку незачем.
# Передаются в suite_core.pure_functions_test параметрами extra_funcs/extra_main.
PURE_EXTRA_FUNCS = (
    ("lib/meshcore/src/mqtt.cpp", "void mqttSlug("),
    ("lib/meshcore/src/fwupdate.cpp", "int fwVersionCmp("),
)

PURE_EXTRA_MAIN = r"""
    // --- fwVersionCmp: сравнение почастям, а не строкой ---
    expect(fwVersionCmp("0.3.10", "0.3.9") > 0, "0.3.10 новее 0.3.9");
    expect(fwVersionCmp("0.1.9", "0.1.10") < 0, "0.1.9 старее 0.1.10");
    expect(fwVersionCmp("1.0.0", "0.9.9") > 0, "1.0.0 новее 0.9.9");
    expect(fwVersionCmp("0.3.6", "0.3.6") == 0, "равные версии");
    expect(fwVersionCmp("0.3.6dev", "0.3.6") == 0, "суффикс dev не считается новее");

    // --- mqttSlug: разные имена не должны давать один slug ---
    char a[48], b[48];
    mqttSlug("Tr1glav_home", a, sizeof(a));
    expect(strcmp(a, "Tr1glav_home") == 0, "латинское имя не меняется");
    mqttSlug("дверь", a, sizeof(a));
    mqttSlug("крыша", b, sizeof(b));
    expect(strcmp(a, b) != 0, "разные кириллические имена дают разный slug");
    mqttSlug("дверь", b, sizeof(b));
    expect(strcmp(a, b) == 0, "одно имя даёт один и тот же slug");
    for (int n = 1; n < 40; n++) {
        char tight[40];
        memset(tight, 'X', sizeof(tight));
        mqttSlug("датчик-в-подвале-очень-длинное-имя", tight, n);
        if (strnlen(tight, (size_t)n) >= (size_t)n) {
            printf("mqttSlug: нет нуля при maxLen=%d\n", n);
            return 1;
        }
    }
"""

PURE_LABEL = "числа, версии, диапазоны настроек и slug для MQTT"

# Минимальный String: fwVersionCmp пользуется только c_str() и indexOf(). Живёт здесь, а не
# в общей части, потому что нужен только этим двум функциям форка.
PURE_EXTRA_PRELUDE = (
    "struct String {\n"
    "  std::string s;\n"
    "  String(const char* p = \"\") : s(p) {}\n"
    "  const char* c_str() const { return s.c_str(); }\n"
    "  int indexOf(char c, int from) const {\n"
    "    size_t p = s.find(c, (size_t)from);\n"
    "    return p == std::string::npos ? -1 : (int)p;\n"
    "  }\n"
    "};\n"
)
