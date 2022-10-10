use base58::{FromBase58, ToBase58};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use serde_yaml;
use libp2p::identity::Keypair;
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::Aead;
use ring::rand::{SecureRandom, SystemRandom};
use chacha20poly1305::KeyInit;
use logger::{InputType, Logger, LogSeverity};

fn argon2_config<'a>() -> argon2::Config<'a> {
    return argon2::Config {
        variant: argon2::Variant::Argon2id,
        hash_length: 32,
        lanes: 8,
        mem_cost: 16 * 1024,
        time_cost: 8,
        ..Default::default()
    };
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SerializableConfig {
    pub private_key_encrypted: String,
    pub nonce: String,
    pub hash: String,
    pub salt: String
}

impl SerializableConfig {
    pub fn new() -> Self {
        Logger::log(LogSeverity::Info, "Config", "Starting setup", None);

        let key = Keypair::generate_ed25519();

        let password = Logger::get_input(InputType::Password, "Enter a password to encrypt your private key with: ");

        let rand = SystemRandom::new();

        let mut salt = [0u8; 32];
        rand.fill(&mut salt).unwrap();

        let mut nonce = [0u8; 24];
        rand.fill(&mut nonce).unwrap();

        let argon_config = argon2_config();

        let chacha_key = argon2::hash_raw(password.as_bytes(), &salt, &argon_config).unwrap();

        let pass_hash = ring::digest::digest(&ring::digest::SHA512, password.as_bytes());

        let cipher = XChaCha20Poly1305::new(chacha_key[..32].as_ref().into());

        let private_key_encrypted = cipher.encrypt(&nonce.into(), key.to_protobuf_encoding().unwrap().as_slice()).unwrap().to_base58();

        let new_cfg = SerializableConfig {
            private_key_encrypted,
            nonce: nonce.to_base58(),
            salt: salt.to_base58(),
            hash: pass_hash.as_ref().to_base58(),
        };

        Logger::log(LogSeverity::Info, "Config", "Setup finished", None);

        new_cfg
    }

    pub fn load() -> Self {
        let config = match std::fs::read_to_string("config.yaml") {
            Ok(config) => config,
            Err(_) => {
                let config = SerializableConfig::new();
                let config_str = serde_yaml::to_string(&config).unwrap();
                std::fs::write("config.yaml", &config_str).unwrap();
                config_str
            }
        };

        serde_yaml::from_str(&config).unwrap()
    }

    pub fn save(&self) {
        let config = serde_yaml::to_string(&self).unwrap();
        std::fs::write("config.yaml", config).unwrap();
    }
}


#[derive(Clone, Debug)]
pub struct Config {
    pub source: SerializableConfig,
    pub keypair: Keypair,
    pub peer_id: PeerId,
}

impl Config {
    pub fn load() -> Config {
        Logger::log(LogSeverity::Info, "Config", "Loading config", None);

        let source = SerializableConfig::load();

        let mut pass_correct = false;
        let mut password = String::new();

        for _i in 0..3 {
            password = Logger::get_input(InputType::Password, "Enter your private key password: ");

            let pass_hash = ring::digest::digest(&ring::digest::SHA512, password.as_bytes());

            if pass_hash.as_ref().to_base58() != source.hash {
                Logger::log(LogSeverity::Error, "Config", "Incorrect password entered", None);
            } else {
                pass_correct = true;
                break;
            }
        }

        if !pass_correct {
            Logger::log(LogSeverity::Fatal, "Config", "Too many incorrect password attempts!", None);
            std::process::exit(1);
        }

        else {
            Logger::log(LogSeverity::Info, "Config", "Correct password entered", None);
        }


        let argon_config = argon2_config();

        let chacha_key = argon2::hash_raw(password.as_bytes(), &source.salt.from_base58().unwrap(), &argon_config).unwrap();

        let cipher = XChaCha20Poly1305::new(chacha_key[..32].as_ref().into());

        let nonce: [u8; 24] = source.nonce.from_base58().unwrap().try_into().unwrap();

        let private_key = match cipher.decrypt(
            &nonce.into(),
            match source.private_key_encrypted.from_base58() {
                Ok(key) => Ok(key),
                Err(_) => Err(Logger::log_then_abort(LogSeverity::Fatal, "Config", "Failed to convert encrypted private key from base 58", None))
            }.unwrap().as_slice()
        ) {
            Ok(key) => Ok(key),
            Err(_) => Err(Logger::log_then_abort(LogSeverity::Fatal, "Config", "Failed to decrypt private key", None))
        }.unwrap();

        let keypair = Keypair::from_protobuf_encoding(&private_key).unwrap();
        let peer_id = PeerId::from(keypair.public());

        Logger::log(LogSeverity::Info, "Config", "Config loaded", None);

        Config {
            source,
            keypair,
            peer_id,
        }
    }

    pub fn save(&mut self) {
        self.source.save();
    }
}