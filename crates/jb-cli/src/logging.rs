//! Единый логгер CLI: весь вывод инструмента идёт через крейт `log` —
//! и шаги сценария, и сообщения доменных крейтов (rockusb, amlogic,
//! jb-core). Формат строки — `HH:MM:SS.mmm LEVEL  сообщение`
//! (UTC, миллисекунды; уровень обязателен — INFO/WARN/ERROR/DEBUG).
//! Вывод в stdout: весь лог в одном потоке, `> файл` ловит всё.
//! Уровень — RUST_LOG (по умолчанию info).

use crate::progress;
use crate::util::ts_ms;
use log::{Log, Metadata, Record};
use std::io::Write;

/// Инициализировать глобальный логгер; вызывается один раз в начале
/// main, до любого вывода.
pub fn init() {
    let inner = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buf, record| {
            writeln!(
                buf,
                "{} {:<5} {}",
                ts_ms(),
                record.level(),
                record.args()
            )
        })
        .target(env_logger::Target::Stdout)
        .build();
    log::set_max_level(inner.filter());
    // Дубликат логгера невозможен (set_boxed_logger в main первым делом),
    // сбой здесь значит ошибку программирования — молча продолжать не
    // надо, но и ронять CLI из-за этого не стоит.
    let _ = log::set_boxed_logger(Box::new(BarAware { inner }));
}

/// Логгер, уступающий строку активной progress-полосе: предупреждения
/// из доменных крейтов приходят и посреди передачи, и без suspend
/// отрисовка бара затирала бы их на терминале.
struct BarAware {
    inner: env_logger::Logger,
}

impl Log for BarAware {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.inner.enabled(metadata)
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        match progress::active_bar() {
            Some(bar) => bar.suspend(|| self.inner.log(record)),
            None => self.inner.log(record),
        }
    }

    fn flush(&self) {
        self.inner.flush();
    }
}
