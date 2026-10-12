// Access mode: only employees listed in ACCESS_KEYS_FILE may initiate sessions.
// Each line is `name<TAB>sk_base64` (64-byte libsodium secret key), '#' starts
// a comment. The employee's public key (base64 of sk[32..]) is configured as
// "key" in the stock client. A missing or unreadable file means nobody is
// allowed (fail-closed). The file is re-read every 5 seconds.
#![allow(dead_code)]

use crate::common::get_arg;
use hbb_common::log;
use once_cell::sync::Lazy;
use sodiumoxide::crypto::sign;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Duration,
};

pub struct Emp {
    pub name: String,
    pub pk: String,
    pub sk: sign::SecretKey,
}

type Emps = HashMap<String, Arc<Emp>>;

static FILE: Lazy<String> = Lazy::new(|| get_arg("ACCESS_KEYS_FILE"));
static EMPS: Lazy<RwLock<Arc<Emps>>> = Lazy::new(|| RwLock::new(Arc::new(HashMap::new())));
const RELOAD_SECS: u64 = 5;

#[inline]
pub fn on() -> bool {
    !FILE.is_empty()
}

/// Active employee with the given public key (base64); always None when off.
pub fn get(pk: &str) -> Option<Arc<Emp>> {
    if pk.is_empty() {
        return None;
    }
    EMPS.read().ok()?.get(pk).cloned()
}

pub fn spawn_reloader() {
    if !on() {
        return;
    }
    log::info!("ACCESS_KEYS_FILE={}", *FILE);
    let mut last = None;
    load(&mut last);
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(RELOAD_SECS));
        load(&mut last);
    });
}

fn load(last: &mut Option<String>) {
    let contents = match std::fs::read_to_string(&*FILE) {
        Ok(contents) => contents,
        Err(err) => {
            if last.as_deref() != Some("") {
                log::error!("Failed to read {}: {}, no employee is allowed", *FILE, err);
            }
            String::new()
        }
    };
    if last.as_ref() == Some(&contents) {
        return;
    }
    let emps = parse(&contents);
    log::info!("Access keys loaded: {} active", emps.len());
    if let Ok(mut lock) = EMPS.write() {
        *lock = Arc::new(emps);
    }
    *last = Some(contents);
}

fn parse(contents: &str) -> Emps {
    let mut emps = HashMap::new();
    for (i, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match line
            .split_once('\t')
            .and_then(|(name, sk)| parse_emp(name.trim(), sk.trim()))
        {
            Some(emp) => {
                emps.insert(emp.pk.clone(), Arc::new(emp));
            }
            None => log::warn!("Access keys line {} is malformed, skipped", i + 1),
        }
    }
    emps
}

fn parse_emp(name: &str, sk: &str) -> Option<Emp> {
    if name.is_empty() {
        return None;
    }
    let bytes = base64::decode(sk).ok()?;
    let sk = sign::SecretKey::from_slice(&bytes)?;
    let pk = base64::encode(&bytes[(sign::SECRETKEYBYTES / 2)..]);
    Some(Emp {
        name: name.to_owned(),
        pk,
        sk,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_keys_parse() {
        let (pk, sk) = sign::gen_keypair();
        let contents = format!(
            "# comment\n\nivanov\t{}\nbroken line\npetrov\tnot-base64\n",
            base64::encode(&sk)
        );
        let emps = parse(&contents);
        assert_eq!(emps.len(), 1);
        let emp = emps.get(&base64::encode(pk)).unwrap();
        assert_eq!(emp.name, "ivanov");
    }
}
