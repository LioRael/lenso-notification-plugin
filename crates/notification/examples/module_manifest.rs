use std::io::{self, Write as _};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = notification::module::manifest();
    let mut output = io::BufWriter::new(io::stdout().lock());
    serde_json::to_writer_pretty(&mut output, &manifest)?;
    writeln!(output)?;
    Ok(())
}
