use serde::Serialize;
use serde_json::{from_str, Value};
use crate::config::{config, status_code};
use crate::key_manager::base_key_manager::CommandExecutor;
use crate::key_manager::openbao_command::Openbao;

#[derive(Serialize)]
pub struct PrivateKey {
    version: String,
    private_key: String,
    algorithm: String,
    encoding: String
}

impl PrivateKey {
    pub fn default() -> PrivateKey {
        Self {
            version: String::new(),
            private_key: String::new(),
            algorithm: String::new(),
            encoding: String::new()
        }
    }

    pub fn new(version: String, private_key: String, algorithm: String, encoding: String) -> Self {
        Self { version, private_key, algorithm, encoding }
    }
}

#[derive(Serialize)]
pub struct PrivateKeyVec {
    fsk: Vec<PrivateKey>,
    nsk: Vec<PrivateKey>,
    tsk: Vec<PrivateKey>
}

impl PrivateKeyVec {
    pub fn default() -> PrivateKeyVec {
        Self {
            fsk: Vec::new(),
            nsk: Vec::new(),
            tsk: Vec::new()
        }
    }

    pub fn new(fsk: Vec<PrivateKey>, nsk: Vec<PrivateKey>, tsk: Vec<PrivateKey>) -> Self {
        Self { fsk, nsk, tsk }
    }
}

pub fn get_all_private_key() -> Result<PrivateKeyVec, i16>{
    let mut bao = Openbao::default();
    let mut vector = PrivateKeyVec::default();
    if !bao.check_status() {
        return Err(status_code::OPENBAO_NOT_AVAILABLE);
    }
    let fsk = get_single_private_key(config::FSK);
    match fsk { 
        Ok(fsk) => {
            vector.fsk = fsk;
        }
        Err(e) => {
            return Err(e);
        }
    }
    let nsk = get_single_private_key(config::NSK);
    match nsk {
        Ok(nsk) => {
            vector.nsk = nsk;
        }
        Err(e) => {
            return Err(e);
        }
    }
    let tsk = get_single_private_key(config::TSK);
    match tsk {
        Ok(tsk) => {
            vector.tsk = tsk;
        }
        Err(e) => {
            return Err(e);
        }
    }
    Ok(vector)
}
fn get_single_private_key(map_name: &str) -> Result<Vec<PrivateKey>, i16> {
    let mut openbao = Openbao::default();
    let mut vec = Vec::<PrivateKey>::new();
    let result = openbao.kv().metadata().get().format_json().mount(&config::SECRET_PATH).map_name(map_name).run();
    let json: Value;
    match result {
        Ok(out) => {
            if !out.status.success() {
                // 当前数据为空
                return Ok(vec);
            }
            json = from_str(&String::from_utf8(out.stdout).unwrap()).unwrap();
        }
        Err(_e) => {
            return Err(status_code::OPENBAO_COMMAND_EXCEPTION);
        }
    }
    let data = json["data"].as_object();
    if data.is_none() {
        // todo 异常
        return Err(status_code::OPENBAO_JSON_ERROR);
    }
    let versions = data.unwrap()["versions"].as_object();
    if versions.is_none() {
        // todo 异常
        return Err(status_code::OPENBAO_JSON_ERROR);
    }
    let tmp_vec: Vec<String> = versions.unwrap().keys().cloned().collect();
    let mut version_vec: Vec<i32> = tmp_vec.iter().map(|item| { item.parse::<i32>().unwrap() }).collect();
    version_vec.sort_by(|item1, item2| item2.cmp(item1));
    for item in version_vec {
        let info = openbao.clean().kv().get().format_json().version(&item).mount(&config::SECRET_PATH).map_name(map_name).run();
        match info {
            Ok(info) => {
                if !info.status.success() {
                    return Err(status_code::OPENBAO_COMMAND_EXECUTE_ERROR);
                }
                let detail_info: Value = from_str(&String::from_utf8(info.stdout).unwrap()).unwrap();
                if !detail_info.is_object() || detail_info.get("data").is_none() {
                    return Err(status_code::OPENBAO_JSON_ERROR);
                }
                let detail_data_json = &detail_info["data"];
                if !detail_data_json.is_object() || detail_data_json.get("data").is_none() {
                    return Err(status_code::OPENBAO_JSON_ERROR);
                }
                let detail_data = &detail_data_json["data"];
                if !detail_data.is_object() || detail_data.get("private_key").is_none() ||  detail_data.get("algorithm").is_none() ||  detail_data.get("encoding").is_some() {
                    return Err(status_code::OPENBAO_JSON_ERROR);
                }
                let private_key = &detail_data["private_key"].to_string();
                let encoding = &detail_data["encoding"].to_string();
                let algorithm = &detail_data["algorithm"].to_string();
                vec.push(PrivateKey::new(item.to_string(), private_key.clone(), algorithm.clone(), encoding.clone()));
            }
            Err(_e) => {
                return Err(status_code::OPENBAO_COMMAND_EXCEPTION);
            }
        }
    }
    Ok(vec)
}