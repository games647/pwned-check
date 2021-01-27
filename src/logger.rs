use log::{Level, LevelFilter, Metadata, Record};

struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, _: &Metadata<'_>) -> bool { true }

    fn log(&self, record: &Record<'_>) {
        if self.enabled(record.metadata()) {
            match record.level() {
                Level::Info | Level::Warn => println!("{}", record.args()),
                Level::Error => eprintln!("{}", record.args()),
                _ => println!("Verbose: {}", record.args())
            }
        }
    }

    fn flush(&self) {}
}

pub fn init(verbose: bool) {
    let mut max_level = LevelFilter::Error;
    if verbose {
        max_level = LevelFilter::Trace;
    }

    log::set_boxed_logger(Box::new(SimpleLogger))
        .map(|()| log::set_max_level(max_level)).unwrap();
}
