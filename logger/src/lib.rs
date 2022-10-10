#![allow(unreachable_code)]

use std::io::Write;
use std::time::{Instant};
use colored::Colorize;
use once_cell::sync::Lazy;
use regex::Regex;

pub enum InputType {
    Plaintext,
    Password
}

pub enum LogSeverity {
    Fatal,
    Error,
    Warn,
    Info,
    Debug
}

#[derive(Clone)]
pub enum LogDestination {
    Stdout,
    File(String)
}

pub struct Logger;

static mut PATTERN: String = String::new();
static mut DESTINATIONS: Vec<LogDestination> = Vec::new();
static mut REGEX_AREA: Lazy<Regex, fn() -> Regex> = Lazy::new(|| { Regex::new(r"\{area}").unwrap() });
static mut REGEX_MESSAGE: Lazy<Regex, fn() -> Regex> = Lazy::new(|| { Regex::new(r"\{message}").unwrap() });
static mut REGEX_SEVERITY: Lazy<Regex, fn() -> Regex> = Lazy::new(|| { Regex::new(r"\{severity}").unwrap() });

static mut START_TIMESTAMP: Lazy<Instant, fn() -> Instant> = Lazy::new(|| { Instant::now() });

impl Logger {
    pub fn set_log_pattern(new_pattern: String) {
        unsafe {
            PATTERN = new_pattern.clone();
        }
    }

    pub fn set_destinations(new_destinations: Vec<LogDestination>) {
        unsafe {
            DESTINATIONS = new_destinations.clone();
        }
    }

    fn get_pattern() -> String {
        unsafe {
            return PATTERN.clone();
        }
    }

    fn get_destinations() -> Vec<LogDestination> {
        unsafe {
            return DESTINATIONS.clone();
        }
    }

    pub fn log(severity: LogSeverity, area: &str, message: &str, severity_caps: Option<bool>) {
        if Logger::get_pattern() == "" {
            Logger::set_log_pattern("[{severity}] {area}: {message}".to_string());
        }

        let mut log_message = Logger::get_pattern();

        let severity_string ={
            let sev = match severity {
                LogSeverity::Fatal => "Fatal",
                LogSeverity::Error => "Error",
                LogSeverity::Warn => "Warn",
                LogSeverity::Info => "Info",
                LogSeverity::Debug => "Debug"
            };

            if severity_caps.is_some() && severity_caps.unwrap() {
                sev.to_uppercase()
            } else {
                String::from(sev)
            }
        };

        unsafe {
            log_message = REGEX_AREA.replace(&log_message, area).to_string();
            log_message = REGEX_MESSAGE.replace(&log_message, message).to_string();
            log_message = REGEX_SEVERITY.replace(&log_message, severity_string).to_string();
        }

        for destination in Logger::get_destinations() {
            match destination {
                LogDestination::Stdout => {
                    match severity {
                        LogSeverity::Fatal => println!("{}", log_message.red()),
                        LogSeverity::Error => println!("{}", log_message.red()),
                        LogSeverity::Warn => println!("{}", log_message.yellow()),
                        LogSeverity::Info => println!("{}", log_message.green()),
                        LogSeverity::Debug => println!("{}", log_message.blue())
                    }
                },
                LogDestination::File(path) => {
                    let timestamp = unsafe { START_TIMESTAMP.elapsed() };

                    let seconds_since_start = timestamp.as_secs_f32();

                    std::fs::OpenOptions::new()
                        .append(true)
                        .create(true)
                        .open(path).unwrap()
                        .write_all(format!("[{seconds_since_start}] {log_message}\n").as_bytes()).unwrap();
                }
            }
        }
    }

    #[allow(unreachable_code)]
    pub fn log_then_abort(severity: LogSeverity, area: &str, message: &str, severity_caps: Option<bool>) -> ! {
        Logger::log(severity, area, message, severity_caps);
        std::process::exit(1);
    }

    pub fn get_input(input_type: InputType, message: &str) -> String {
        match input_type {
            InputType::Plaintext => {
                let mut input = String::new();
                print!("{}", message.blue());
                std::io::stdin().read_line(&mut input).unwrap();
                input
            },
            InputType::Password => {
                match rpassword::prompt_password(message.blue()) {
                    Ok(input) => input,
                    Err(_) => {
                        Logger::log_then_abort(LogSeverity::Fatal, "Logger", "Failed to read password", None);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pass_input() {
        let password = Logger::get_input(InputType::Password, "Enter 'test': ");
        assert_eq!(password, "test");
    }
}