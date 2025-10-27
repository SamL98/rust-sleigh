pub trait Logger {
    fn should_log(&self) -> bool;
    fn depth(&self) -> usize;
    fn inc_depth(&mut self);
    fn dec_depth(&mut self);
}

#[macro_export]
macro_rules! log {
    ($context:expr, $fmt:expr) => {
        if $context.should_log() {
            print!("{}", " ".repeat($context.depth() * 3));
            println!($fmt);
        }
    };
    ($context:expr, $fmt:expr, $($arg:tt)*) => {
        if $context.should_log() {
            print!("{}", " ".repeat($context.depth() * 3));
            println!($fmt, $($arg)*);
        }
    };
}
