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

use std::cmp::Ordering;
use std::ops::Add;
use serde::ser::SerializeMap;

use regex::Regex;

use crate::config::println_verbose;

use super::zone;
use super::query;

use std::sync::{Arc};
use std::sync::RwLock;

#[derive(Serialize, Deserialize)]
pub struct NameServer {
	pub server_name : String,
	pub ip : std::net::IpAddr,
	pub speed : Option<std::time::Duration>
}

impl NameServer {

	pub fn new( zone_record : &zone::record::ZoneRecord ) -> NameServer {

		NameServer {
			server_name : zone_record.name.fqdn.clone(),
			ip : zone::record::ZoneRecord::record_to_address(zone_record).expect("record passed into NameServer is not A or AAAA record"),
			speed: None
		}

	}
}

impl Clone for NameServer {

	fn clone(&self) -> Self {
		Self {
			server_name : self.server_name.clone(),
			ip: self.ip.clone(),
			speed: self.speed.clone()
		}
	}

}

#[derive(Serialize, Deserialize)]
pub struct NameServersForZone	 {
	pub zone_name : String,
	pub servers : Vec< NameServer >
}

impl NameServersForZone {
	pub fn new( zone_name : &String ) -> Self {
		Self {
			zone_name : zone_name.clone(),
			servers: Vec::new()
		}
	}

	pub fn sort( &mut self ) {
		self.servers.sort_by(|a,b| {

			if a.speed.is_none() && b.speed.is_none() {
				Ordering::Equal
			} else if a.speed.is_some() && b.speed.is_none() {
				Ordering::Less
			} else if a.speed.is_none() && b.speed.is_some() {
				Ordering::Greater
			} else {
				a.speed.partial_cmp(&b.speed).unwrap()
			}
		});
	}
}

impl Clone for NameServersForZone {
	
	fn clone(&self) -> Self {
		Self { 
			zone_name: self.zone_name.clone(), 
			servers: self.servers.clone() 
		}
	}
}


pub struct Root {
	pub zone : zone::Zone,
	pub root_addr : std::collections::hash_map::HashMap< String, std::sync::Arc<RwLock<NameServersForZone>> >,

	nameservers : std::collections::hash_map::HashMap::<String, Vec< zone::record::ZoneRecord >>,
	addresses : std::collections::hash_map::HashMap::<String, Vec< zone::record::ZoneRecord >>

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
						self.nameservers.entry(rec.name.fqdn.clone()).or_insert_with( || Vec::new() ).push( rec.clone() );
					} else if rec.record_type == zone::record::RecordType::A || rec.record_type == zone::record::RecordType::AAAA {
						self.addresses.entry(rec.name.fqdn.clone()).or_insert_with(|| Vec::new()).push( rec.clone() );			
					}
				},
				None => {}
			}
		}

		for (zone_name, zone_record) in &mut self.nameservers {

			for server in zone_record.iter_mut() {
				if let Some(rdata) = &mut server.rdata {
					if let Some(ns_rr) = rdata.as_mut().as_any_mut().downcast_mut::<zone::rr::RDATANameRR>() {
						if let Some(i) = self.addresses.get_mut( &ns_rr.name.fqdn.clone() ) {
							let e = self.root_addr.entry(zone_name.clone()).or_insert_with(|| std::sync::Arc::new(RwLock::new( NameServersForZone::new(&zone_name))));
							for zr in i {
								e.write().unwrap().servers.push( NameServer::new(zr));
							}
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
	pub fn get_nameservers(&mut self, domain_name : &String) -> Result< std::sync::Arc<RwLock<NameServersForZone>>, String> {

		let name_split = Self::split_name(domain_name);
		let mut zone_name : String = String::new();

		let mut last_ns : Option< std::sync::Arc<RwLock<NameServersForZone>> > = None;
		
		for zn in name_split.iter().rev() {
			let mut _zone_name = zn.clone();
			_zone_name.push_str(zone_name.as_str());

			if let Some(ns) = self.root_addr.get(&_zone_name) {
				last_ns = Some( Arc::clone(ns) );
				zone_name.clone_from(&_zone_name);
			} else { break; }
		}

		if let Some(n) = last_ns {
			return Ok(n);
		}

		Err(format!("Did not find the zone '{}'", zone_name).to_string())

	}

	/*
	 This function works more or less like get_nameservers except for 2nd level extensions that are not 
	 in the list will be added. To prevent this going nuts we are only supporting tld and second level domains like
	 bob.it.com
	 */
	pub fn get_nameservers_and_resolve(&mut self, domain_name : &String) -> Result<std::sync::Arc<RwLock<NameServersForZone>>, String> {

		let mut last_ns : Option< std::sync::Arc<RwLock< NameServersForZone> > > = None;
		let mut zone_name : String = String::new();
		let mut zone_ctr = 0;

		let spl = Self::split_name(domain_name);

		for zn in spl.iter().rev() {
			let mut _zone_name = zn.clone();
			_zone_name.push_str(zone_name.as_str());			

			if let Some(ns) = self.root_addr.get(&_zone_name) {
				last_ns = Some(ns.clone());
				zone_name = _zone_name.clone();
				zone_ctr = zone_ctr + 1;
			} else { 
				
				if zone_ctr == 1 && spl.len() > 2 { 

					// this block is for resolving additional "root" nameservers, these are usuually either fake
					// root nameservers for a fake extension like it.com, or 2nd level domains in country codes
					// that are real but are on different servers than their normal root.
					println_verbose!(VERBOSE2, "Did not find '{}', attempting to resolve", _zone_name);

					if let Some(last_ns_s) = &last_ns {

						for rec in &last_ns_s.read().unwrap().servers {
							let mut sender = query::Sender::new( &rec.ip );
							if let Err(e) = sender.query(&_zone_name, query::QueryType::T_NS) {
								println_verbose!(VERBOSE2, "Error querying '{}': {}", _zone_name, e);
								continue;
							}

							let mut needs_ip : Vec<String> = Vec::new();

							let zone_ns = std::sync::Arc::new(RwLock::new(NameServersForZone {
								zone_name: _zone_name.clone(),
								servers: Vec::new()
							}));
							let mut zone_ns_w = zone_ns.write().unwrap();

							println_verbose!(VERBOSE3, "'{}' '{}'", _zone_name, sender.recv_header);

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
														println_verbose!(VERBOSE2, "Adding '{}' for '{}'", addrrec, _zone_name);
														zone_ns_w.servers.push(NameServer::new(addrrec));
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
											zone_ns_w.servers.push( NameServer {
												server_name : name.clone(),
												ip: addr, 
												speed: None
											});
										}
									}
								}

								self.root_addr.insert(_zone_name.clone(), Arc::clone(&zone_ns));

								println_verbose!(VERBOSE1, "Resolved {} ips for {}", zone_ns_w.servers.len(), _zone_name);

								return Ok( Arc::clone(&zone_ns) );

							}
							
						}

					} else {
						println_verbose!(VERBOSE1, "No parent nameserver for {}", _zone_name);
					}

					break;
				} else {
					break;
				}
			}
		}

		if let Some(n) = last_ns {
			return Ok( n );
		}

		Err("nameserver not found".to_string())
	}

	/**
	 * this function will test the dns servers and sort them by
	 * how fast they are, the thread_ct is how many threads that
	 * are going to be used
	 */
	pub fn performance_test(&mut self, thread_ct : usize) {

		let mut server_ct = 0;

		for (_zone_name, ns_zone) in &self.root_addr {
			server_ct = server_ct + ns_zone.read().unwrap().servers.len();
		}

		// split up the servers into different vectors so we can pass them through to the threads
		let mut ctr = 0;

		let mut threads : Vec<std::thread::JoinHandle<()>> = Vec::new();

		let mut ips : Vec< std::sync::Arc< RwLock< Vec< std::sync::Arc< RwLock< NameServersForZone >> >> >> = Vec::new();

		for _ in 0..thread_ct {
			ips.push(std::sync::Arc::new( RwLock::new(Vec::new())));
		}

		for (_zone, root_ns) in self.root_addr.iter() {
			ips[ctr].write().unwrap().push( Arc::clone(root_ns) );

			ctr = ctr + 1;
			if ctr >= thread_ct {
				ctr = 0;
			}
		}

		while let Some(ip_list ) = ips.pop() {
			threads.push(std::thread::spawn(move || {
				Root::test_main( ip_list );
			}));
		}

		for thread in threads {
			thread.join().unwrap();
		}



	}

	/**
	 * thread main for testing the inputted list of nameservers
	 */
	fn test_main( ip_list : std::sync::Arc<RwLock<Vec<std::sync::Arc<RwLock<NameServersForZone>>>>> ) {

		for zone_ns in ip_list.write().unwrap().iter() {

			let root_ns = &mut zone_ns.write().unwrap();

			let zone_str = root_ns.zone_name.clone();

			let itr = &mut root_ns.servers;

			for server in itr {

				let mut durations = std::time::Duration::new(0,0);

				let mut is_ok = false;

				for _ in 0..5 {

					let start = std::time::SystemTime::now();

					let mut sender = query::Sender::new( &server.ip );
					match sender.query(& zone_str, query::QueryType::T_SOA) {
						Ok(()) => { 
							is_ok = true;
							durations = durations.add( start.elapsed( ).unwrap() );
						},
						Err(_) => {
							
						}
					}


				}

				if is_ok { 
					server.speed = Some( durations.div_f32( 5f32 ) );
				} else {
					server.speed = None;
				}

				println_verbose!(VERBOSE1, "Server {} Time {:?}", server.server_name, server.speed);

			}

			root_ns.sort();

		}

	}

	/**
	 * write this to a json and return it
	 */
	pub fn to_json( &self ) -> String {
		serde_json::to_string( &self ).unwrap()
	}

	/**
	 * replace the root_addr serialized from the inputted cache file
	 */
	pub fn cache_from_js( &mut self, serialized : &String ) {
		self.root_addr = serde_json::from_str::<Root>(serialized).unwrap().root_addr.clone();
	}

}

impl serde::Serialize for Root {

	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer 
	{
		let mut map = serializer.serialize_map(Some(self.root_addr.len()))?;
		for (k, v) in &self.root_addr {
			map.serialize_entry(k, &*v.read().unwrap())?;
		}
		map.end()
	}
}


impl<'de> serde::Deserialize<'de> for Root {

	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de> 
	{
		
		let mut rval = Self {
			zone: Default::default(),
			root_addr: Default::default(),
			nameservers: Default::default(),
			addresses: Default::default()
		};

		let visitor = RootVisitor {};

		rval.root_addr.clear();

		match deserializer.deserialize_map(visitor) {
			Ok( m ) => {
				for (k,v) in m {
					rval.root_addr.insert(k, Arc::new(RwLock::new(v.clone())));
				}
			},
			Err( e ) => {
				return Err(e);
			}
		}

		Ok(rval)
	}
}

struct RootVisitor {

}

impl<'de> serde::de::Visitor<'de> for RootVisitor {
	
	type Value = std::collections::hash_map::HashMap< String, NameServersForZone >;

	fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
		formatter.write_str("cache output")
	}

	fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
	where
		M: serde::de::MapAccess<'de>,
	{
		let mut map = Self::Value::with_capacity(access.size_hint().unwrap_or(0));

		// While there are entries remaining in the input, add them
		// into our map.
		while let Some((key, value)) = access.next_entry()? {
			map.insert(key, value);
		}

		Ok(map)
	}

}

impl std::fmt::Display for Root {

	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		
		for (zone_name, records) in &self.root_addr {
			write!(f, "\nZone: '{}'", zone_name)?;

			for rec in &records.write().unwrap().servers {
				write!(f, "\n\t{} {:?}", rec.ip, rec.speed)?;
			}
		}
				
		Ok(())
	}
}