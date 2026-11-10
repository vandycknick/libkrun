use std::io::{self, Write};

use krun::api::capabilities::{live_state_schema, query_live_host};

fn main() -> io::Result<()> {
    let report = query_live_host();
    let mut output = io::stdout().lock();
    writeln!(output, "{report:#?}")?;
    writeln!(output, "live_state_schema: {}", live_state_schema())
}
