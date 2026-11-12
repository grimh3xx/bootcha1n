//! Findings model and the three output channels shared by every grimh3xx
//! auditor: colored terminal, JSON, and SARIF 2.1.0 (GitHub code scanning).
//!
//! The exit code is the worst severity *shown* (0 none/info .. 4 critical) so
//! the tool can gate a CI job or a fleet-compliance script directly.

use anstream::println;
use owo_colors::OwoColorize;
use serde::Serialize;
use serde_json::{json, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "info" | "none" => Some(Self::Info),
            "low" => Some(Self::Low),
            "medium" | "med" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" | "crit" => Some(Self::Critical),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }

    pub fn exit_code(self) -> u8 {
        self as u8
    }

    fn sarif_level(self) -> &'static str {
        match self {
            Self::Critical | Self::High => "error",
            Self::Medium => "warning",
            Self::Low | Self::Info => "note",
        }
    }

    /// CVSS-like numeric hint GitHub uses to bucket `security-severity`.
    fn security_severity(self) -> &'static str {
        match self {
            Self::Critical => "9.5",
            Self::High => "8.0",
            Self::Medium => "5.5",
            Self::Low => "3.0",
            Self::Info => "0.0",
        }
    }

    fn painted(self) -> String {
        let tag = format!("{:<8}", self.label());
        match self {
            Self::Critical => tag.on_red().white().bold().to_string(),
            Self::High => tag.red().bold().to_string(),
            Self::Medium => tag.yellow().bold().to_string(),
            Self::Low => tag.cyan().to_string(),
            Self::Info => tag.dimmed().to_string(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub id: &'static str,
    pub severity: Severity,
    pub title: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub detail: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub remediation: String,
    /// Where the evidence came from (a sysfs node, a registry value, a file).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
}

impl Finding {
    pub fn new(id: &'static str, severity: Severity, title: impl Into<String>) -> Self {
        Self {
            id,
            severity,
            title: title.into(),
            detail: String::new(),
            remediation: String::new(),
            source: None,
            evidence: Vec::new(),
        }
    }

    pub fn detail(mut self, d: impl Into<String>) -> Self {
        self.detail = d.into();
        self
    }

    pub fn fix(mut self, r: impl Into<String>) -> Self {
        self.remediation = r.into();
        self
    }

    pub fn source(mut self, s: impl Into<String>) -> Self {
        self.source = Some(s.into());
        self
    }

    pub fn evidence(mut self, e: impl Into<String>) -> Self {
        self.evidence.push(e.into());
        self
    }
}

/// Keep findings at or above `min`, most severe first, stable by id.
pub fn filter_sort(mut findings: Vec<Finding>, min: Severity) -> Vec<Finding> {
    findings.retain(|f| f.severity >= min);
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.id.cmp(b.id)));
    findings
}

pub fn worst(findings: &[Finding]) -> u8 {
    findings
        .iter()
        .map(|f| f.severity.exit_code())
        .max()
        .unwrap_or(0)
}

pub fn section(title: &str) {
    println!();
    println!("  {} {}", "▌".cyan(), title.bold());
}

pub fn kv(key: &str, value: impl std::fmt::Display) {
    println!("    {:<26} {}", key.dimmed(), value);
}

pub fn print_findings(findings: &[Finding]) {
    section("findings");
    if findings.is_empty() {
        println!("    {}", "no findings at the selected severity".green());
        return;
    }
    for f in findings {
        println!();
        println!(
            "    {} {}  {}",
            f.severity.painted(),
            f.id.bright_blue(),
            f.title.bold()
        );
        if !f.detail.is_empty() {
            for line in wrap(&f.detail, 86) {
                println!("             {}", line);
            }
        }
        for e in &f.evidence {
            println!("             {} {}", "·".dimmed(), e.dimmed());
        }
        if let Some(src) = &f.source {
            println!("             {} {}", "src".dimmed(), src.dimmed());
        }
        if !f.remediation.is_empty() {
            let mut lines = wrap(&f.remediation, 80).into_iter();
            if let Some(first) = lines.next() {
                println!("             {} {}", "fix".green(), first);
            }
            for line in lines {
                println!("                 {}", line);
            }
        }
    }
}

pub fn print_summary(findings: &[Finding]) {
    let count = |s: Severity| findings.iter().filter(|f| f.severity == s).count();
    println!();
    println!(
        "  {} {} critical · {} high · {} medium · {} low · {} info",
        "Σ".cyan().bold(),
        count(Severity::Critical).red().bold(),
        count(Severity::High).red(),
        count(Severity::Medium).yellow(),
        count(Severity::Low).cyan(),
        count(Severity::Info).dimmed(),
    );
}

fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    for para in text.split('\n') {
        let mut line = String::new();
        for word in para.split_whitespace() {
            if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > width {
                out.push(std::mem::take(&mut line));
            }
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(word);
        }
        out.push(line);
    }
    out
}

/// SARIF 2.1.0 log. Host-level findings have no source file, so the evidence
/// source (or `fallback_uri`) is used as the artifact location; GitHub code
/// scanning rejects results without a location.
pub fn sarif(
    tool: &str,
    version: &str,
    info_uri: &str,
    fallback_uri: &str,
    findings: &[Finding],
) -> Value {
    let mut rule_ids: Vec<&str> = findings.iter().map(|f| f.id).collect();
    rule_ids.sort_unstable();
    rule_ids.dedup();

    let rules: Vec<Value> = rule_ids
        .iter()
        .map(|id| {
            let f = findings.iter().find(|f| f.id == *id).expect("rule from findings");
            json!({
                "id": id,
                "name": id.replace('-', ""),
                "shortDescription": { "text": f.title },
                "help": { "text": if f.remediation.is_empty() { f.title.clone() } else { f.remediation.clone() } },
                "properties": {
                    "security-severity": f.severity.security_severity(),
                    "tags": ["security", "hardening"],
                },
            })
        })
        .collect();

    let results: Vec<Value> = findings
        .iter()
        .map(|f| {
            let uri = f
                .source
                .as_deref()
                .unwrap_or(fallback_uri)
                .trim_start_matches('/')
                .replace('\\', "/");
            let mut text = f.title.clone();
            if !f.detail.is_empty() {
                text.push_str(" — ");
                text.push_str(&f.detail);
            }
            json!({
                "ruleId": f.id,
                "level": f.severity.sarif_level(),
                "message": { "text": text },
                "locations": [{
                    "physicalLocation": { "artifactLocation": { "uri": uri } }
                }],
                "properties": { "severity": f.severity, "evidence": f.evidence },
            })
        })
        .collect();

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": tool,
                "version": version,
                "informationUri": info_uri,
                "rules": rules,
            }},
            "results": results,
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worst_is_max_severity() {
        let f = vec![
            Finding::new("A-1", Severity::Low, "a"),
            Finding::new("A-2", Severity::High, "b"),
        ];
        assert_eq!(worst(&f), 3);
        assert_eq!(worst(&[]), 0);
    }

    #[test]
    fn filter_drops_and_sorts() {
        let f = vec![
            Finding::new("B", Severity::Info, "i"),
            Finding::new("A", Severity::Medium, "m"),
            Finding::new("C", Severity::Critical, "c"),
        ];
        let out = filter_sort(f, Severity::Medium);
        assert_eq!(out.iter().map(|f| f.id).collect::<Vec<_>>(), ["C", "A"]);
    }

    #[test]
    fn sarif_has_location_for_every_result() {
        let f = vec![Finding::new("X-1", Severity::High, "t").source("/sys/x")];
        let s = sarif("t", "0", "u", "host", &f);
        assert_eq!(
            s["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"],
            "sys/x"
        );
        assert_eq!(s["runs"][0]["results"][0]["level"], "error");
    }
}
