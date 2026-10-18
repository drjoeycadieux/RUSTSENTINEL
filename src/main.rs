use colored::*;
use reqwest::Client;
use std::time::Instant;

#[derive(Debug, Clone)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    fn colorize(&self) -> ColoredString {
        match self {
            Severity::Low => "LOW".blue(),
            Severity::Medium => "MEDIUM".yellow(),
            Severity::High => "HIGH".bright_red(),
            Severity::Critical => "CRITICAL".red().bold(),
        }
    }
}

#[derive(Debug)]
pub struct WebFinding {
    pub severity: Severity,
    pub category: String,
    pub target: String,
    pub description: String,
}

fn print_banner() {
    println!("{}", "========================================================".bright_cyan());
    println!("{}", "      🌐  WEB SENTINEL // DAST SECURITY SCANNER         ".bright_cyan().bold());
    println!("{}", "========================================================".bright_cyan());
}

async fn audit_security_headers(client: &Client, url: &str) -> Vec<WebFinding> {
    let mut findings = Vec::new();
    
    let resp = match client.get(url).send().await {
        Ok(r) => r,
        Err(e) => {
            println!("[-] Failed to connect to target: {}", e);
            return findings;
        }
    };

    let headers = resp.headers();

    // Check Server Header (Information Disclosure)
    if let Some(server) = headers.get("server") {
        if let Ok(server_str) = server.to_str() {
            findings.push(WebFinding {
                severity: Severity::Low,
                category: "Information Disclosure".into(),
                target: url.to_string(),
                description: format!("Server header reveals software version: '{}'", server_str),
            });
        }
    }

    // Check X-Powered-By Header
    if let Some(powered) = headers.get("x-powered-by") {
        if let Ok(powered_str) = powered.to_str() {
            findings.push(WebFinding {
                severity: Severity::Low,
                category: "Information Disclosure".into(),
                target: url.to_string(),
                description: format!("X-Powered-By header reveals tech stack: '{}'", powered_str),
            });
        }
    }

    // Check HSTS (Strict-Transport-Security)
    if !headers.contains_key("strict-transport-security") {
        findings.push(WebFinding {
            severity: Severity::Medium,
            category: "Missing Security Header".into(),
            target: url.to_string(),
            description: "Missing 'Strict-Transport-Security' (HSTS) header.".into(),
        });
    }

    // Check Content Security Policy (CSP)
    if !headers.contains_key("content-security-policy") {
        findings.push(WebFinding {
            severity: Severity::Medium,
            category: "Missing Security Header".into(),
            target: url.to_string(),
            description: "Missing 'Content-Security-Policy' (CSP) header, increasing XSS risk.".into(),
        });
    }

    // Check X-Frame-Options (Clickjacking protection)
    if !headers.contains_key("x-frame-options") {
        findings.push(WebFinding {
            severity: Severity::Medium,
            category: "Missing Security Header".into(),
            target: url.to_string(),
            description: "Missing 'X-Frame-Options' header (Clickjacking vulnerability).".into(),
        });
    }

    findings
}

async fn scan_sensitive_endpoints(client: &Client, base_url: &str) -> Vec<WebFinding> {
    let mut findings = Vec::new();
    let base_trimmed = base_url.trim_end_matches('/');

    // Common sensitive paths to probe
    let paths = vec![
        ("/.git/HEAD", Severity::Critical, "Exposed Git repository folder (.git/HEAD). Source code can be dumped."),
        ("/.env", Severity::Critical, "Exposed environment configuration file (.env). May contain plaintext API keys/passwords."),
        ("/robots.txt", Severity::Low, "Robots.txt file found (review for hidden administrative paths)."),
        ("/swagger.json", Severity::Medium, "Exposed API Swagger documentation endpoint."),
        ("/backup.zip", Severity::High, "Exposed backup archive file."),
        ("/server-status", Severity::Medium, "Exposed Apache server-status page."),
    ];

    let mut tasks = vec![];

    for (path, severity, desc) in paths {
        let client_clone = client.clone();
        let target_url = format!("{}{}", base_trimmed, path);
        
        tasks.push(tokio::spawn(async move {
            if let Ok(resp) = client_clone.get(&target_url).send().await {
                // If status is 200 OK, the file exists!
                if resp.status().as_u16() == 200 {
                    return Some(WebFinding {
                        severity,
                        category: "Exposed Sensitive Asset".into(),
                        target: target_url,
                        description: desc.to_string(),
                    });
                }
            }
            None
        }));
    }

    for task in tasks {
        if let Ok(Some(finding)) = task.await {
            findings.push(finding);
        }
    }

    findings
}

#[tokio::main]
async fn main() {
    print_banner();
    let start_time = Instant::now();

    // Target URL from CLI args or default example
    let args: Vec<String> = std::env::args().collect();
    let target_url = if args.len() > 1 {
        args[1].clone()
    } else {
        eprintln!("Usage: cargo run -- <URL>");
        eprintln!("Example: cargo run -- https://example.com");
        std::process::exit(1);
    };

    println!("[*] Initializing scan against target: {}\n", target_url.cyan());

    // Build custom reqwest client with timeout and spoofed user agent
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .danger_accept_invalid_certs(true) // Helpful for testing self-signed dev/staging certs
        .user_agent("WebSentinel-Security-Scanner/1.0")
        .build()
        .unwrap();

    let mut all_findings = Vec::new();

    // 1. Audit Headers
    println!("[*] Auditing HTTP security headers...");
    let header_findings = audit_security_headers(&client, &target_url).await;
    all_findings.extend(header_findings);

    // 2. Fuzz Sensitive Files
    println!("[*] Probing for exposed sensitive files and endpoints...");
    let endpoint_findings = scan_sensitive_endpoints(&client, &target_url).await;
    all_findings.extend(endpoint_findings);

    let duration = start_time.elapsed();

    // Report Results
    println!("\n{}", "==================== DAST SCAN RESULTS ====================".bright_cyan());
    if all_findings.is_empty() {
        println!("{}", "✨ No security issues or missing headers detected on target!".green().bold());
    } else {
        println!("Found {} potential issue(s):\n", all_findings.len());

        for (idx, finding) in all_findings.iter().enumerate() {
            println!(
                "[{}] [{}] {} -> {}",
                format!("{:02}", idx + 1).bright_black(),
                finding.severity.colorize(),
                finding.category.bold(),
                finding.target.cyan()
            );
            println!("    Description: {}\n", finding.description);
        }
    }

    println!("{}", "============================================================".bright_cyan());
    println!("Scan completed in {:.2?}", duration);
}