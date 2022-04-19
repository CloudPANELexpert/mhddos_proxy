import os
from threading import Lock
from typing import Dict, Tuple

from tabulate import tabulate

from .core import cl, logger, THREADS_PER_CORE
from .mhddos import Tools


class Stats:

    def __init__(self):
        self._requests: int = 0
        self._bytes: int = 0
        self._lock = Lock()

    def __iadd__(self, value: Tuple[int, int]):
        self.increment(value)
        return self

    def get(self) -> Tuple[int, int]:
        with self._lock:
            return self._requests, self._bytes

    def increment(self, value: Tuple[int, int]):
        requests, bytes = value
        with self._lock:
            self._requests += requests
            self._bytes += bytes

    def reset(self) -> Tuple[int, int]:
        with self._lock:
            current = self._requests, self._bytes
            self._requests, self._bytes = 0, 0
        return current


def cls():
    os.system('cls' if os.name == 'nt' else 'clear')


def show_statistic(
    statistics: Dict["Params", Stats],
    refresh_rate,
    table,
    vpn_mode,
    proxies_cnt,
    period,
    passed
):
    tabulate_text = []
    total_pps, total_bps = 0, 0
    for params, stats in statistics.items():
        rs, bs = stats.reset()
        pps = int(rs / refresh_rate)
        total_pps += pps
        bps = int(8 * bs / refresh_rate)
        total_bps += bps
        if table:
            tabulate_text.append((
                f'{cl.YELLOW}%s' % params.target.url.host, params.target.url.port, params.method,
                Tools.humanformat(pps) + "/s", f'{Tools.humanbits(bps)}/s{cl.RESET}'
            ))
        else:
            logger.info(
                f'{cl.YELLOW}Ціль:{cl.BLUE} %s,{cl.YELLOW} Порт:{cl.BLUE} %s,{cl.YELLOW} Метод:{cl.BLUE} %s'
                f' {cl.YELLOW} Запити:{cl.BLUE} %s/s,{cl.YELLOW} Трафік:{cl.BLUE} %s/s{cl.RESET}' %
                (
                    params.target.url.host,
                    params.target.url.port,
                    params.method,
                    Tools.humanformat(pps),
                    Tools.humanbits(bps),
                )
            )

    if table:
        tabulate_text.append((f'{cl.GREEN}Усього', '', '', Tools.humanformat(total_pps) + "/s",
                              f'{Tools.humanbits(total_bps)}/s{cl.RESET}'))

        cls()
        print(tabulate(
            tabulate_text,
            headers=[f'{cl.BLUE}Ціль', 'Порт', 'Метод', 'Запити', f'Трафік{cl.RESET}'],
            tablefmt='fancy_grid'
        ))
        print_banner(vpn_mode)
    else:
        logger.info(
            f'{cl.GREEN}Усього:{cl.YELLOW} Запити:{cl.GREEN} %s/s,{cl.YELLOW} Трафік:{cl.GREEN} %s/s{cl.RESET}' %
            (
                Tools.humanformat(total_pps),
                Tools.humanbits(total_bps),
            )
        )

    print_progress(period, passed, proxies_cnt)


def print_progress(period, passed, proxies_cnt):
    logger.info(f'{cl.YELLOW}Новий цикл через: {cl.BLUE}{round(period - passed)} секунд{cl.RESET}')
    if proxies_cnt:
        logger.info(f'{cl.YELLOW}Кількість проксі: {cl.BLUE}{proxies_cnt}{cl.RESET}')
    else:
        logger.info(f'{cl.YELLOW}Атака без проксі - переконайтеся що ви анонімні{cl.RESET}')


def print_banner(vpn_mode):
    print(f'''
- {cl.YELLOW}Навантаження (кількість потоків){cl.RESET} - параметр `-t 3000`, за замовчуванням - CPU * {THREADS_PER_CORE}
- {cl.YELLOW}Статистика у вигляді таблиці або тексту{cl.RESET} - прапорець `--table` або `--debug`
- {cl.YELLOW}Повна документація{cl.RESET} - https://github.com/porthole-ascend-cinnamon/mhddos_proxy
    ''')

    if not vpn_mode:
        print(
            f'        {cl.MAGENTA}Щоб використовувати VPN або власний IP замість проксі - додайте прапорець `--vpn`{cl.RESET}\n')
