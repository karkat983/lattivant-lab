//! Run the integrated lab and print the ground-truth matrix and a sample report.

use lattivant_lab::{reset, run, Variant};

fn main() {
    println!("Lattivant integrated lab — scenario matrix\n");
    println!("{:<30} {:<22} {:<22} {:<6}", "variant", "expected", "derived", "ok");
    println!("{}", "-".repeat(82));
    for variant in Variant::all() {
        let r = run(variant);
        println!(
            "{:<30} {:<22} {:<22} {:<6}",
            variant.label(),
            format!("{:?}", r.expected),
            format!("{:?}", r.derived),
            if r.matches_ground_truth() { "yes" } else { "NO" },
        );
    }
    println!("\nclean-reset reproduces ground truth: {}", reset::reproduces());

    let achieved = run(Variant::AchievedCrossTenantWrite);
    println!("\n--- sample investigation report (achieved variant) ---\n");
    println!("{}", achieved.report_markdown);
}
