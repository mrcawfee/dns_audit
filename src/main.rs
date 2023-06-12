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

use std::{io::{Write, stdout, Read, stderr}, process::exit, sync::{Arc, RwLock, Mutex}, fs::File, thread::sleep, time::Duration};

use monitor::Monitor;

use crate::config::println_verbose;

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
	opts.optopt("c", "", "JSON Configuration file, or - for stdin", "file");
	opts.optopt("", "cache-out", "write cache file", "FILE");
	opts.optopt("", "cache-in", "read cache file", "FILE");
	opts.optopt("o", "", "Write results as JSON, or - for stdout", "FILE");
	opts.optopt("w", "watch", "Keep running until any change", "# seconds");
	opts.optflag("","all", "When this flag is on, all results are written. when absent only errors are shown");
	opts.optflagmulti("v", "verbose", "Verbose Mode");
	opts.optflag("h", "help", "Help");
	opts.optopt("", "threads", "how many threads are used for testing, default 1", "#");

	let matches = match opts.parse(&args[1..]) {
		Ok(m) => { m }
		Err(e) => { 
			writeln!(stderr().lock(), "{}", opts.usage( &e.to_string() )).unwrap(); 
			exit(1); 
		}
	};

	if matches.opt_present("h") {
		writeln!(stderr().lock(), "{}", opts.usage("")).unwrap();
		exit(1);
	}

	*crate::config::VERBOSE.write().unwrap() = matches.opt_count("v");

	let watch : Option<Duration> = match matches.opt_get::<u64>("w") {
		Ok(w) =>  { 
			match w {
				Some(w2) => Some( Duration::new(w2,0) ),
				None => None
			}
		}
		Err(e) => {
			writeln!(stderr().lock(), "{}", opts.usage( &format!("-w is invald: {}", e) )).unwrap(); 
			exit(1); 
		}
	};
	let all = matches.opt_present("all");

	let file_name: String = match matches.opt_str("root-zone") {
		Some(m) => { m },
		None => { 
			writeln!(stderr().lock(), "{}", opts.usage("root-zone is required")).unwrap();
			exit(1);
		}
	};
	
	let mut local_config : Vec<monitor::Monitor>;
	match matches.opt_str("c") {
		Some(json_file) => { 

			let mut json_contents: String;

			if json_file == "-" {

				json_contents = String::new();

				if let Err(e) = std::io::stdin().lock().read_to_string(&mut json_contents) {
					panic!("{}", e);
				}
				
			} else {
				json_contents = std::fs::read_to_string(&json_file).expect("failed to read JSON");
			}
		
			local_config = match serde_json::from_str::<Vec<monitor::Monitor>>(json_contents.as_str() ) {
				Ok( m ) =>  { m },
				Err(e ) => { panic!("{}", e); }
			};

		 },
		None => { 
			local_config = Vec::new();
		}
	};

	let root = match root::Root::create(&file_name, &".".to_string()) {
		Ok(m) => { Arc::new(RwLock::new(m)) },
		Err(e) => { panic!("{}", e); }
	};

	let out_fp : Arc<RwLock<Box<dyn std::io::Write>>> = Arc::new(RwLock::new(Box::new(stdout())));
	if let Some(out_fn ) = &matches.opt_str("o") {

		if out_fn != "-" {
			*(out_fp.write().unwrap()) = Box::new(match File::create(out_fn) {
				Ok(fp) => { fp }
				Err(e) => { panic!("failed to open {} for writing {}", out_fn, e) }
			});
		}
	}

	if let Some(cachefn) = matches.opt_str("cache-in" ) {

		match std::fs::read_to_string(cachefn) {
			Ok( str ) => {
				root.write().unwrap().cache_from_js(&str);
			},
			Err( e ) =>  {
				panic!("{}", e.to_string())
			}
		}
		
	} else if let Some(cachefn) = matches.opt_str("cache-out") {

		write!(stderr().lock(), "Testing Root Nameservers... ").unwrap();
		root.write().unwrap().performance_test(20);
		writeln!(stderr().lock(), "Complete!").unwrap();

		match &mut std::fs::File::create(cachefn) {
			Ok(fp) => { 
				fp.write_all( root.write().unwrap().to_json().as_bytes() ).expect("Failed to write");
				fp.flush().expect("failed to flush");
			},
			Err(e) => { panic!("{}", e.to_string()) }
		};
		
	}

	if local_config.len() == 0  {
		writeln!(stderr().lock(), "Nothing to test").unwrap();
		exit(1);
	}

	let mut config : Vec<Arc<RwLock<monitor::Monitor>>> = Vec::new();

	let thread_ct = match matches.opt_get::<i32>("threads") {
		Ok(v) => {
			match v {
				Some(z) => { z }
				None => { 1 }
			}
		}
		Err(_) => { 1 }
	};

	while let Some(c) = local_config.pop() {
		config.push( Arc::new(RwLock::new(c)));
	}
	
	for m in &mut config {
		m.write().unwrap().normalize();
	}

	let code : Arc<Mutex<i32>> = Arc::new(Mutex::new(0));

	let mut requests : Vec< std::sync::Arc< RwLock< Vec< std::sync::Arc< RwLock< Monitor >> >> >> = Vec::new();

	let mut monitor_iter = config.iter();
	for _ in 0..thread_ct {
		let mut list = Vec::< std::sync::Arc< RwLock< Monitor >>>::new();
		for _ in 0..((config.len() as f32 / thread_ct as f32).ceil() as i32){
			if let Some(m) = monitor_iter.next() {
				list.push(Arc::clone(m));
			}
		}
		requests.push(Arc::new(RwLock::new(list)));
	}


	loop {

		let lcode = code.clone();

		let results : Arc<Mutex<Vec<Arc<Mutex<monitor::MonitorResult>>>>> = Arc::new(Mutex::new(Vec::new()));

		let mut thread_iter = requests.iter();

		let mut threads : Vec<std::thread::JoinHandle<()>> =  Vec::new();

		println_verbose!(VERBOSE2, "starting with {} threads", requests.len());

		while let Some(_thread_list) = thread_iter.next() {
			let thread_list = Arc::clone(_thread_list);
			let result_loc = Arc::clone(&results);
			let root = Arc::clone(&root);
			let code = Arc::clone(&code);
			threads.push(std::thread::spawn(move || {

				let list = & thread_list.read().unwrap();

				for m in list.iter(){
					let res = monitor::Monitor::test( m.clone(), root.clone() );
					
					if all || !res.lock().unwrap().success {
						
						let res_lock = res.lock().unwrap();
						
						if !res_lock.success {
							*(code.lock().unwrap()) = 2;
						}
						result_loc.lock().unwrap().push(res.clone());
		
					}
					
				}

				println_verbose!(VERBOSE2, "Thread complete");
			}));
		}

		for thr in threads { 
			if let Err(_) = thr.join() { }
		}

		out_fp.write().unwrap().write_all(serde_json::to_string( &*results.lock().unwrap() ).unwrap().as_bytes()).unwrap();

		if watch.is_none()  || *lcode.lock().unwrap() != 0 {
			break;
		}

		sleep(watch.unwrap().clone() );

	}


	exit(code.lock().unwrap().clone());
}
