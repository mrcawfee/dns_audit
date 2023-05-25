pub mod zone;
pub mod root;
pub mod dns;

extern crate getopts;
extern crate ascii;

fn main() {

	let args: Vec<String> = std::env::args().collect();

	let mut opts = getopts::Options::new();
	opts.reqopt("f", "", "Root zone file path", "PATH");
	opts.optopt("o", "", "Origin Domain", "Domain Name");
	opts.optopt("d", "", "Domain", "Domain Name");

	let matches = match opts.parse(&args[1..]) {
		Ok(m) => { m }
		Err(f) => { panic!("{}", f.to_string()) }
	};

	let file_name: String = match matches.opt_str("f") {
		Some(m) => { m },
		None => { panic!("f is required") }
	};
	
	let mut origin: String = match matches.opt_str("o") {
		Some(m) => { m },
		None => { String::new() }
	};

	if !origin.ends_with(".") {
		origin += ".";
	}

	let mut root = match root::Root::create(&file_name, &origin) {
		Ok(m) => { m },
		Err(e) => { panic!("{}", e); }
	};

	match matches.opt_str("d") {
		Some(domain_name ) => { 
			match root.get_nameservers( &domain_name ) {
				Ok(servers)  => {
					println!("Root Servers for {}", domain_name);
					for server in servers {
						if let Some(rd) = &server.rdata {
							println!("\t{}", rd);

							if let Some(rec) = rd.as_any().downcast_ref::<zone::rr::RDATAa>() {
								let ip_addr : std::net::IpAddr = std::net::IpAddr::from( rec.ip );
								let mut sender = dns::Sender::new( &ip_addr );
								if let Err(e) = sender.query(&ascii::AsciiString::from_ascii( domain_name.as_str()).unwrap(), dns::QueryType::T_NS) {
									panic!("Error {}", e);
								}
								break;
							}
							
						}

						
						
					}
				},
				Err(e) => { panic!("{}", e); }
			}
		},
		None => {  }
	};

}
