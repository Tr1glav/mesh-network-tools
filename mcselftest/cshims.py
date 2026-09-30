"""Заглушки Arduino для хостовых сборок.

Вырезанные из прошивки функции написаны под Arduino, а собираются обычным g++: им нужны
random() и String, которых на хосте нет. Куски лежат отдельно, потому что нужны сразу
нескольким наборам проверок — и ядру (пауза флуда), и форку (кнопки в MQTT).
"""


# random() на хосте: считаем и выдаём заранее заданную последовательность, чтобы проверка
# границ не зависела от того, что выдаст генератор. На плате random() не бывает вне
# диапазона, здесь нам важно проверить саму формулу выбора паузы.
RANDOM_PRELUDE = r"""
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
static unsigned long rndNext = 12345;
static long lastRandomLo = 0, lastRandomHi = 0;
static unsigned int lastRandom = 0;
void srandom(unsigned int s) { rndNext = s; }
unsigned int random(unsigned int howbig) {
    lastRandomLo = 0; lastRandomHi = (long)howbig;
    if (howbig == 0) { lastRandom = 0; return 0; }
    rndNext = rndNext * 1103515245UL + 12345UL;
    lastRandom = (unsigned int)((rndNext >> 16) % howbig);
    return lastRandom;
}
// Второй перегруз — как в Arduino: [min, max), и min обязан быть не больше max.
// Ширину диапазона проверяет вызывающий код, а не random: если min > max, Arduino
// возвращает min, и это тоже ловится — неверный результат, а не зависание.
long random(long howsmall, long howbig) {
    lastRandomLo = howsmall; lastRandomHi = howbig;
    if (howsmall >= howbig) return howsmall;
    return howsmall + (long)random((unsigned int)(howbig - howsmall));
}
"""


# Своя копия Arduino String: bareButton пользуется ровно этим набором. Собственная, а не
# общая с PURE_PRELUDE, потому что набор нужен другой и несовместимый.
STRING_PRELUDE = r"""
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
struct String {
    std::string s;
    String(const char* p = "") : s(p) {}
    const char* c_str() const { return s.c_str(); }
    size_t length() const { return s.size(); }
    bool startsWith(const char* p) const { return s.rfind(p, 0) == 0; }
    char operator[](size_t i) const { return s[i]; }
    String substring(size_t a, size_t b) const { return String(s.substr(a, b - a).c_str()); }
    bool operator==(const char* p) const { return s == p; }
};
"""

