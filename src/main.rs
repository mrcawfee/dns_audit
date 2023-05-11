pub mod zone;
extern crate getopts;

fn main() {

	let args: Vec<String> = std::env::args().collect();

	let mut opts = getopts::Options::new();
	opts.reqopt("f", "", "Zone file path", "PATH");

	let matches = match opts.parse(&args[1..]) {
		Ok(m) => { m }
		Err(f) => { panic!("{}", f.to_string()) }
	};

	let file_name: String = match matches.opt_str("f") {
		Some(m) => { m },
		None => { panic!("f is required") }
	};
	

	let zone = match zone::Zone::create(&file_name)  {
		Ok(m) => { m },
		Err(e) => { panic!("Error '{}' for file '{}' ", e, file_name) }
	};

}
