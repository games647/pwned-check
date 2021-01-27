use log::{Level, LevelFilter, Metadata, Record};

struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &Record<'_>) {
        if self.enabled(record.metadata()) {
            match record.level() {
                Level::Error => eprintln!("{}", record.args()),
                Level::Info | Level::Warn => println!("{}", record.args()),
                _ => println!("Verbose: {}", record.args()),
            }
        }
    }

    fn flush(&self) {}
}

fn set_verbose_level(verbose: bool) {
    let mut max_level = LevelFilter::Info;
    if verbose {
        max_level = LevelFilter::Trace;
    }

    log::set_max_level(max_level);
}

pub fn set_logger(verbose: bool) {
    // Safety: safe, because we set it globally once
    log::set_boxed_logger(Box::new(SimpleLogger)).unwrap();

    set_verbose_level(verbose);
}

#[cfg(test)]
mod test {
    use super::*;

    fn is_allowed(level: Level) -> bool {
        level <= log::max_level()
    }

    #[test]
    fn test_not_verbose() {
        set_verbose_level(false);

        assert!(is_allowed(Level::Error));
        assert!(is_allowed(Level::Info));
        assert!(!is_allowed(Level::Debug));
    }

    #[test]
    fn test_verbose() {
        set_verbose_level(true);

        assert!(is_allowed(Level::Error));
        assert!(is_allowed(Level::Info));
        assert!(is_allowed(Level::Debug));
    }
}
