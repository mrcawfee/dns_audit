
pub mod record;
pub mod tokenizer;
pub mod rr;

pub struct Zone {
	pub records: Vec<Box<dyn record::IZoneRecord> >

}

impl Zone {

	pub fn create( filename : & String, __origin : &String ) -> Result<Zone, String> { 

		let mut zone: Zone = Default::default();

		let token_lines = tokenizer::ZoneLines::create(filename)?;

		for line in token_lines.lines {

			match record::ZoneRecord::create(&line) {
				Err(e) => { return Err(e); },
				Ok(m) => { 
					zone.records.push( m ); 
				}
			}
		}

		let mut origin = __origin.clone();
		let mut ttl: i32 = 0;

		for record in &mut zone.records {

			match record.as_any().downcast_ref::<record::ZoneDirective>() {
				Some(b) => {
					if b.name.eq_ignore_ascii_case( "ORIGIN") {
						origin = b.value.clone();
					} else if b.name.eq_ignore_ascii_case("TTL") {
						match b.value.parse::<i32>() {
							Ok(t) => { ttl = t }, 
							Err(_e) => { }
						}
					}
				},
				None => { }
			}

			match record.as_any().downcast_mut::<record::ZoneRecord>() {

				Some(b) => {
					b.origin(&origin);
					if b.ttl == 0 {
						b.ttl = ttl;
					}
				},
				None => {}
			}


		}

		return Ok(zone);
	}

}

impl Default for Zone {
	fn default() -> Self {
		Zone {
			records: Vec::new()
		}
	}
}