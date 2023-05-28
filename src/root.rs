use regex::Regex;

use crate::config::println_verbose;

use super::zone;
use super::query;
extern crate unicase;

pub struct Root {
	pub zone : zone::Zone,
	pub root_addr : std::collections::hash_map::HashMap< unicase::Ascii<String>, Vec< zone::record::ZoneRecord > >,

	nameservers : std::collections::hash_map::HashMap::<unicase::Ascii<String>, Vec< zone::record::ZoneRecord >>,
	addresses : std::collections::hash_map::HashMap::<unicase::Ascii<String>, Vec< zone::record::ZoneRecord >>

}

impl Root {

	pub fn create( file_name : &String, origin : &String )  -> Result< Self, String > {

		let mut rval = Root {
			zone: match zone::Zone::create(&file_name, &origin)  {
				Ok(m) => { m },
				Err(e) => { return Err(e) }
			},
			root_addr: std::collections::hash_map::HashMap::new(),
			nameservers: std::collections::hash_map::HashMap::new(),
			addresses: std::collections::hash_map::HashMap::new(),
		};

		rval.from_file()?;

		Ok(rval)
	}

	pub fn from_file<'a>( &'a mut self) -> Result< (), String > {

		for record in &mut self.zone.records {

			let zone_record = record.as_any().downcast_mut::<zone::record::ZoneRecord>();
			match zone_record {
				Some(rec) => {

					if rec.record_type == zone::record::RecordType::NS {
						self.nameservers.entry(unicase::Ascii::new(rec.name.fqdn.clone())).or_insert_with( || Vec::new() ).push( rec.clone() );
					} else if rec.record_type == zone::record::RecordType::A || rec.record_type == zone::record::RecordType::AAAA {
						self.addresses.entry(unicase::Ascii::new(rec.name.fqdn.clone())).or_insert_with(|| Vec::new()).push( rec.clone() );			
					}
				},
				None => {}
			}
		}

		for (zone_name, zone_record) in &mut self.nameservers {

			for server in zone_record.iter_mut() {
				if let Some(rdata) = &mut server.rdata {
					if let Some(ns_rr) = rdata.as_mut().as_any_mut().downcast_mut::<zone::rr::RDATANameRR>() {
						if let Some(i) = self.addresses.get_mut( &unicase::Ascii::new(ns_rr.name.fqdn.clone()) ) {
							self.root_addr.entry(zone_name.clone()).or_insert_with(|| Vec::new()).append( &mut i.clone() );
						}
					}
				}
			}
		}

		Ok(())
	}

	/*
		split_name()

		Split a domain name by it's zones while honoring the bind escape
		\ character.

		Return: split domain name into different zones
	 */
	pub fn split_name( domain_name : &String ) -> Vec<String> {

		let delim = Regex::new(r"(([^\\])|(^))\.").unwrap();

		let mut last : usize  = 0;

		let mut spl : Vec<String> = Vec::new();

		for mat in delim.find_iter(domain_name) {

			let mut s = domain_name[last..(mat.start())].to_string();
			let m = mat.as_str().to_string();

			if m.len() == 2 && m[0..1] != *"\\"  {
				s.push_str(&m[0..1]);
			}

			spl.push(s);

			last = mat.end();
		}

		if last < domain_name.len() - 1 {
			spl.push(domain_name[last..].to_string());
		}

		let mut rval = Vec::<String>::new();

		for n in spl {

			let mut str = n.to_string();
			str.push('.');
			rval.push( str );
		}

		return rval;
	}

	/**
	 get a list of nameservers for the indicated domain, this will stop looking for 
	 nameservers once it can't find a new zone, for example bob.jones.com will stop at .com 
	 because jones doesn't exist, if you want to resolve jones.com as a "root" use the 
	 get_nameservers_and_resolve function
	 */
	pub fn get_nameservers(&mut self, domain_name : &String) -> Result<&Vec< zone::record::ZoneRecord >, String> {

		let name_split = Self::split_name(domain_name);
		let mut zone_name : String = String::new();

		let mut last_ns : Option< &Vec<zone::record::ZoneRecord > > = None;
		
		for zn in name_split.iter().rev() {
			let mut _zone_name = zn.clone();
			_zone_name.push_str(zone_name.as_str());

			let _zone_ascii = unicase::Ascii::new( _zone_name );

			if let Some(ns) = self.root_addr.get(&_zone_ascii) {
				last_ns = Some(ns);
				zone_name.clone_from(&_zone_ascii.to_string());
			} else { break; }
		}

		if let Some(n) = last_ns {
			return Ok(&n);
		}

		Err(format!("Did not find the zone '{}'", zone_name).to_string())

	}

	/*
	 This function works more or less like get_nameservers except for 2nd level extensions that are not 
	 in the list will be added. To prevent this going nuts we are only supporting tld and second level domains like
	 bob.it.com
	 */
	pub fn get_nameservers_and_resolve(&mut self, domain_name : &String) -> Result<Vec< zone::record::ZoneRecord >, String> {

		let mut last_ns : Option< Vec<zone::record::ZoneRecord > > = None;
		let mut zone_name : String = String::new();
		let mut zone_ctr = 0;

		let spl = Self::split_name(domain_name);

		for zn in spl.iter().rev() {
			let mut _zone_name = zn.clone();
			_zone_name.push_str(zone_name.as_str());			

			let _zone_ascii = unicase::Ascii::new( _zone_name );

			if let Some(ns) = self.root_addr.get(&_zone_ascii) {
				last_ns = Some(ns.clone());
				zone_name = _zone_ascii.to_string();
				zone_ctr = zone_ctr + 1;
			} else { 
				
				if zone_ctr == 1 { 

					// this block is for resolving additional "root" nameservers, these are usuually either fake
					// root nameservers for a fake extension like it.com, or 2nd level domains in country codes
					// that are real but are on different servers than their normal root.
					println_verbose!(VERBOSE2, "Did not find '{}', attempting to resolve", _zone_ascii);

					if let Some(last_ns_s) = &last_ns {

						for rec in last_ns_s {
							if let Some(ip_addr) = zone::record::ZoneRecord::record_to_address(&rec) {
								let mut sender = query::Sender::new( &ip_addr );
								if let Err(e) = sender.query(&ascii::AsciiString::from_ascii(  _zone_ascii.to_string().as_str()).unwrap(), query::QueryType::T_NS) {
									println_verbose!(VERBOSE2, "Error querying '{}': {}", _zone_ascii, e);
									continue;
								}

								let mut needs_ip : Vec<String> = Vec::new();
								let mut ips : Vec<zone::record::ZoneRecord> = Vec::new();
		
								println_verbose!(VERBOSE3, "'{}' '{}'", _zone_ascii, sender.recv_header);

								if sender.recv_header.rcode == query::RCODE::NOERROR {

									// we got an address, yay.
									for rec in &sender.authority {
										if rec.record_type == zone::record::RecordType::NS {

											let mut found : bool = false;

											if let Some(rdata) = &rec.rdata {
												if let Some(val) = rdata.as_any().downcast_ref::<zone::rr::RDATANameRR>() {

													for addrrec in &sender.additional {
														if (addrrec.record_type == zone::record::RecordType::A || addrrec.record_type == zone::record::RecordType::AAAA) && addrrec.name.fqdn.eq_ignore_ascii_case( &val.name.fqdn ) {
															found = true;
															println_verbose!(VERBOSE2, "Adding '{}' for '{}'", addrrec, _zone_ascii);
															ips.push(addrrec.clone());
														}
													}
												}
											}

											if !found {
												needs_ip.push( rec.name.fqdn.clone());
											}

										}
									}

									// go through the servers that we need ip addresses for 
									// that were not in the glue and resolve them the old fashioned way.
									for name in needs_ip {
										if let Ok( addresses ) = dns_lookup::lookup_host( &name ) {
											for addr in addresses {

												let mut rec : zone::record::ZoneRecord =  Default::default() ;
												rec.name.name = name.clone();
												rec.name.fqdn = name.clone();

												match addr {
													std::net::IpAddr::V4(ip4) => {
														rec.record_type = zone::record::RecordType::A;
														rec.rdata = Some( Box::new(zone::rr::RDATAa {
															ip : ip4.clone()
														}));
													},
													std::net::IpAddr::V6(ip6) => {
														rec.record_type = zone::record::RecordType::AAAA;
														rec.rdata = Some( Box::new(zone::rr::RDATAaaaa {
															ip : ip6.clone()
														}));
													}
												}

												println_verbose!(VERBOSE2, "Adding '{}' for '{}'", addr, _zone_ascii);

												ips.push( rec );
											}
										}
									}

									self.root_addr.entry(_zone_ascii.clone()).or_insert_with(|| ips.clone());

									println_verbose!(VERBOSE1, "Resolved {} ips for {}", ips.len(), _zone_ascii);


									return Ok(ips.clone());

								}

							}
							
						}

					} else {
						println_verbose!(VERBOSE1, "No parent nameserver for {}", _zone_ascii);
					}

					break;
				} else {
					break;
				}
			}
		}

		if let Some(n) = &last_ns {
			return Ok(n.clone());
		}

		Err("nameserver not found".to_string())
	}

}

impl std::fmt::Display for Root {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		
		for (zone_name, records) in &self.root_addr {
			write!(f, "\nZone: '{}'", zone_name)?;

			for rec in records {
				if let Some(ip) = &rec.rdata {
					write!(f, "\n\t{}", ip)?;
				}
			}
		}
		        
		Ok(())
    }
}