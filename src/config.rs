


lazy_static!(
	pub static ref VERBOSE : std::sync::RwLock<usize> = std::sync::RwLock::new(0);
);

pub const VERBOSE_NONE : usize = 0;
pub const VERBOSE1 : usize = 1;
pub const VERBOSE2 : usize = 2;
pub const VERBOSE3 : usize = 3;

macro_rules! println_verbose {
	($level:ident) => {
		if *crate::config::VERBOSE.read().unwrap() >= crate::config::$level {
			println!();
		}
	};
	($level:ident, $($args:expr),*) => {
		if *crate::config::VERBOSE.read().unwrap() >= crate::config::$level {
			println!($($args),*);
		}
	};
}

macro_rules! print_verbose {
	($level:ident) => {
		if *crate::config::VERBOSE.read().unwrap() >= crate::config::$level {
			print!();
		}
	};
	($level:ident, $($args:expr),*) => {
		if *crate::config::VERBOSE.read().unwrap() >= crate::config::$level {
			print!($($args),*);
		}
	};
}

pub(crate) use println_verbose;
pub(crate) use print_verbose;
