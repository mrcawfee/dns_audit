/**
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

use std::{io::{Write, stdout}, process::exit, sync::{Arc, RwLock}, fs::File};

pub mod zone;
pub mod root;
pub mod query;
pub mod config;
pub mod monitor;

extern crate getopts;
extern crate ascii;
#[macro_use]
extern crate lazy_static;
extern crate dns_lookup;
extern crate serde_json;
extern crate serde;

#[macro_use]
extern crate serde_derive;

fn main() {

	let args: Vec<String> = std::env::args().collect();

	let mut opts = getopts::Options::new();
	opts.optopt("", "root-zone", "Root zone file path", "PATH");
	opts.reqopt("c", "", "file", "JSON Configuration file");
	opts.optopt("", "cache-out", "write cache file", "FILE");
	opts.optopt("", "cache-in", "read cache file", "FILE");
	opts.optopt("o", "", "Write results as JSON", "FILE");
	opts.optflag("w", "watch", "Keep running until any change");
	opts.optflag("","all", "When this flag is on, all results are written. when absent only errors are shown");
	opts.optflagmulti("v", "verbose", "Verbose Mode");

	let matches = match opts.parse(&args[1..]) {
		Ok(m) => { m }
		Err(f) => { panic!("{}", f.to_string()) }
	};

	*crate::config::VERBOSE.write().unwrap() = matches.opt_count("v");

	let watch = matches.opt_present("w");
	let all = matches.opt_present("all");

	let file_name: String = match matches.opt_str("root-zone") {
		Some(m) => { m },
		None => { panic!("f is required") }
	};
	
	let json_file: String = match matches.opt_str("c") {
		Some(m) => { m },
		None => { String::new() }
	};

	let mut root = match root::Root::create(&file_name, &".".to_string()) {
		Ok(m) => { m },
		Err(e) => { panic!("{}", e); }
	};

	let mut out_fp : Option<Box<dyn std::io::Write>> = None;

	if let Some(out_fn ) = &matches.opt_str("o") {

		if out_fn == "-" {
			out_fp = Some( Box::new(stdout().lock()) );
		} else {
			let fp: Box<File> = match File::create(out_fn) {
				Ok(fp) => { Box::new(fp) }
				Err(e) => { panic!("failed to open {} for writing {}", out_fn, e) }
			};
			out_fp = Some(fp);
		}
	}

	if let Some(cachefn) = matches.opt_str("cache-in" ) {

		match std::fs::read_to_string(cachefn) {
			Ok( str ) => {
				root.cache_from_js(&str);
			},
			Err( e ) =>  {
				panic!("{}", e.to_string())
			}
		}
		
	} else if let Some(cachefn) = matches.opt_str("cache-out") {

		root.performance_test(20);

		match &mut std::fs::File::create(cachefn) {
			Ok(fp) => { 
				fp.write_all( root.to_json().as_bytes() ).expect("Failed to write");
				fp.flush().expect("failed to flush");
			},
			Err(e) => { panic!("{}", e.to_string()) }
		};
		
	}

	let mut local_config = match serde_json::from_str::<Vec<monitor::Monitor>>(std::fs::read_to_string(&json_file).expect("failed to read JSON").as_str() ) {
		Ok( m ) =>  { m },
		Err(e ) => { panic!("{}", e); }
	};

	let mut config : Vec<Arc<RwLock<monitor::Monitor>>> = Vec::new();

	while let Some(c) = local_config.pop() {
		config.push( Arc::new(RwLock::new(c)));
	}
	
	for m in &mut config {
		m.write().unwrap().normalize();
	}

	let mut code = 0;

	loop {
		
		let mut results : Vec<monitor::MonitorResult> = Vec::new();

		for m in &config {
			let res = monitor::Monitor::test( &m, &mut root );
			if all || !res.success {
				if out_fp.is_none() {
					writeln!(std::io::stdout().lock(), "{}", res).unwrap();
				}
				if !res.success {
					code = 1;
				}

				results.push(res);

			}
		}

		if let Some(fp) = &mut out_fp {
			fp.write_all(serde_json::to_string( &results ).unwrap().as_bytes()).unwrap();
		}

		if !watch || code != 0 {
			break;
		}

	}


	exit(code);
}
