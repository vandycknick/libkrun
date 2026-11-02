use std::io::{self, Write};

use krun::api::capabilities::query_live_host;

fn main() -> io::Result<()> {
    let report = query_live_host();
    let mut output = io::stdout().lock();
    writeln!(output, "{report:#?}")?;
    writeln!(
        output,
        "build_binding_complete: {}",
        report.build.binding_complete()
    )
}
