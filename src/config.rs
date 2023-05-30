/*
DNS Audit Tool

(c) 2023 Benjamin P Wilder, All Rights Reserved

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

*/

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
