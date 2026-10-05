"""Цели проверки: что запускать и где искать исходники.

Цель — это ответ на два вопроса: какие наборы проверок прогнать и в каком каталоге лежит
проверяемая прошивка. Всё остальное (пути к ядру, вырезание функций, сборка на хосте) общее.

Добавить прошивку — добавить сюда запись и, если у неё есть свои проверки, модуль
suite_<имя>.py рядом. Больше нигде трогать ничего не нужно.
"""
import pathlib

from . import suite_core, suite_fork, suite_font, suite_tdeck


def _core_checks(ctx, host_extra=None, pure_extra=None):
    """Проверки ядра — общие для всех целей, в том же порядке, в каком они шли раньше в
    scripts/selftest.py каждого форка. Порядок сохранён намеренно: по нему привыкли читать
    вывод, и перестановка выглядела бы как исчезнувшая проверка."""
    host_extra = host_extra or {}
    pure_extra = pure_extra or {}
    suite_core.host_functions_test(ctx, **host_extra)
    suite_core.pure_functions_test(ctx, **pure_extra)
    suite_core.marker_scan_test(ctx)
    suite_core.otaz_test(ctx)
    suite_core.flood_gap_test(ctx)
    suite_core.ota_first_burst_test(ctx)
    suite_core.ota_slow_test(ctx)
    suite_core.ota_slow_recovery_test(ctx)
    suite_core.ota_slow_applied_test(ctx)
    suite_core.weak_hooks_test(ctx)
    suite_core.ota_screen_progress_test(ctx)
    suite_core.any_session_test(ctx)
    suite_core.relay_default_off_test(ctx)
    suite_core.features_defined_test(ctx)
    suite_core.loss_counters_live_test(ctx)
    suite_core.meshcore_copies_test(ctx)
    suite_core.sensor_tasks_in_core_test(ctx)
    suite_core.button_in_core_test(ctx)
    suite_core.peer_cache_test(ctx)
    suite_core.group_text_bound_test(ctx)
    suite_core.cfg_reply_queue_test(ctx)
    suite_core.airtime_budget_test(ctx)
    suite_core.secrets_example_test(ctx)
    suite_core.provision_console_budget_test(ctx)
    suite_core.flood_gap_name_test(ctx)
    suite_core.tools_ref_branch_test(ctx)
    suite_core.relay_queue_test(ctx)
    suite_core.fast_rx_isolation_test(ctx)
    suite_core.handshake_budget_test(ctx)
    suite_core.timing_budgets_test(ctx)
    suite_core.build_commits_test(ctx)


def run_core(ctx):
    """Только ядро: ни одной прошивки рядом может и не быть.

    Часть проверок ядра всё же смотрит в прошивки (например, что ни один features.h не
    переопределяет FEATURE_RELAY). Они сами переживают отсутствие форка — проверять там
    нечего, и молчание честнее выдуманного «OK»."""
    _core_checks(ctx)


def run_fork(ctx):
    """meshcore-fork: ядро плюс своё — страница координатора, кнопки в MQTT, приложение."""
    _core_checks(ctx,
                 pure_extra=dict(extra_funcs=suite_fork.PURE_EXTRA_FUNCS,
                                 extra_main=suite_fork.PURE_EXTRA_MAIN,
                                 extra_prelude=suite_fork.PURE_EXTRA_PRELUDE,
                                 label=suite_fork.PURE_LABEL))
    suite_fork.button_compat_test(ctx)
    suite_fork.companion_bounds_test(ctx)
    # Страница проверяется цепочкой: page_js_test читает web/app.js и передаёт его дальше —
    # разбор разметки, маршруты и поля /info нужны все от одного и того же текста.
    suite_fork.page_js_test(ctx)


def run_tdeck(ctx):
    """tdeck: ядро плюс своё — пакет приложения, шапка ELF и кириллица в шрифтах."""
    _core_checks(ctx,
                 host_extra=dict(extra_funcs=suite_tdeck.HOST_EXTRA_FUNCS,
                                 extra_main=suite_tdeck.HOST_EXTRA_MAIN,
                                 extra_label=suite_tdeck.HOST_EXTRA_LABEL))
    suite_tdeck.tapp_test(ctx)
    suite_tdeck.elf_headers_test(ctx)
    suite_tdeck.elf_sections_test(ctx)
    suite_font.cyrillic_font_test(ctx)


# Имя цели -> (каталог прошивки относительно рабочего дерева, что запускать, пояснение).
# Каталог — это значение по умолчанию: его перебивает ключ --root и переменная окружения.
TARGETS = {
    "core":  ("mesh-network-core", run_core,  "только ядро протокола"),
    "fork":  ("meshcore-fork",     run_fork,  "прошивки Heltec: координатор, узел, прошивальщик, компаньон"),
    "tdeck": ("tdeck",             run_tdeck, "прошивка LilyGO T-Deck"),
}


def default_root(name, tree):
    """Каталог прошивки по умолчанию: сосед в том же рабочем дереве."""
    return pathlib.Path(tree) / TARGETS[name][0]
