
struct ZoneToken {

};

type ZoneTokens = Vector<ZoneToken>;


fn tokenize_zone_file( filename : &str ) -> Result<ZoneTokens, io::Error> { 

    ZoneTokens rval = ZoneTokens::new();

    let mut file = match std::fs::File::open(filename) {
        Ok(x) => { x },
        Err(e) => return Err(e)
    };


    return Ok(rval);
}