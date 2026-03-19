// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, Context, Result};
use iddqd::IdHashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use toml::map::Map;

use dice_verifier::ipcc::AttestIpcc;
use dice_verifier::AttestMock;
use vm_attest::{Measurement, VmInstanceConf};
use vm_attest::{Request, Response, VmInstanceAttester, VmInstanceRot};

use crate::config::{
    AttestationBackend, AttestationConfig, Config, Device, FileConfig,
    VsockDevice,
};
use propolis::vsock::proxy::VsockPortMapping;

const MAX_LINE_LENGTH: usize = 1024;
const ATTEST_PORT: u32 = 605;

pub fn get_sockaddr_from_vsock_mapping(
    device: &VsockDevice,
) -> Result<SocketAddr> {
    let port_mappings: IdHashMap<&VsockPortMapping> =
        device.port_mappings.iter().collect();

    Ok(port_mappings
        .get(&ATTEST_PORT)
        .with_context(|| format!("get port mapping for port {ATTEST_PORT}"))?
        .addr()
        .clone())
}

pub fn get_path_for_block_device(
    config: &Config,
    dev: &Device,
    log: &slog::Logger,
) -> Result<PathBuf> {
    slog::info!(log, "get_file_path_for_block_device");
    let backend_name = dev
        .options
        .get("block_dev")
        .ok_or(anyhow!("no `block_dev` found for block device"))?
        .as_str()
        .ok_or(anyhow!("`block_dev` field in block device is not a string"))?;

    let be = config
        .block_devs
        .get(backend_name)
        .ok_or(anyhow!("No block device named \"{backend_name}\""))?;

    match &be.bdtype as &str {
        "file" => {
            let map = Map::from_iter(be.options.clone());
            let config: FileConfig =
                map.try_into().context("map backend options to FileConfig")?;
            slog::info!(log, "FileConfig: {config:?}");
            Ok(PathBuf::from(config.path))
        }
        _ => todo!("handle non-file backends: crucible?"),
    }
}

pub fn parse_cfg(cfg: AttestationConfig) -> Result<VmInstanceRot> {
    let uuid = uuid::Uuid::parse_str(&cfg.instance_uuid)
        .context("Parse UUID string")?;
    let boot_digest: Measurement = cfg
        .boot_digest
        .parse()
        .context("boot_digest to vm_attest::Measurement")?;
    let vm_conf = VmInstanceConf { uuid, boot_digest: Some(boot_digest) };

    let ox_attest: Box<dyn dice_verifier::Attest> = match cfg.backend {
        AttestationBackend::Mock => {
            let pki_path = cfg
                .pki_path
                .as_ref()
                .context("pki_path required for mock backend")?;
            let log_path = cfg
                .log_path
                .as_ref()
                .context("log_path required for mock backend")?;
            let alias_key_path = cfg
                .alias_key_path
                .as_ref()
                .context("alias_key_path required for mock backend")?;
            Box::new(
                AttestMock::load(pki_path, log_path, alias_key_path)
                    .context("AttestMock load artifacts")?,
            )
        }
        AttestationBackend::Ipcc => {
            Box::new(AttestIpcc::new().context("Create AttestIpcc")?)
        }
    };

    Ok(VmInstanceRot::new(ox_attest, vm_conf))
}

pub fn run_server(
    log: &slog::Logger,
    rot: VmInstanceRot,
    listener: TcpListener,
) -> Result<()> {
    let mut msg = String::new();
    for client in listener.incoming() {
        slog::info!(log, "new client connected");

        // create `BufReader` w/ capacity & `take` reader w/ same limit
        let reader = BufReader::with_capacity(MAX_LINE_LENGTH, client?);
        let mut limited_reader = reader.take(MAX_LINE_LENGTH as u64);

        slog::info!(log, "LISTENING");

        loop {
            let bytes_read = limited_reader.read_line(&mut msg)?;

            if bytes_read == 0 {
                break;
            }

            // Check if the limit was hit and a newline wasn't found
            if bytes_read == MAX_LINE_LENGTH && !msg.ends_with('\n') {
                slog::warn!(
                    log,
                    "Error: Line length exceeded the limit of {} bytes.",
                    MAX_LINE_LENGTH
                );
                let response = Response::Error("Request too long".to_string());
                let mut response = serde_json::to_string(&response)?;
                response.push('\n');
                slog::info!(log, "sending error response: {response}");
                limited_reader
                    .get_mut()
                    .get_mut()
                    .write_all(response.as_bytes())?;
                break;
            }

            slog::debug!(log, "JSON received: {msg}");

            let result: Result<Request, serde_json::Error> =
                serde_json::from_str(&msg);
            let request = match result {
                Ok(q) => q,
                Err(e) => {
                    let response = Response::Error(e.to_string());
                    let mut response = serde_json::to_string(&response)?;
                    response.push('\n');
                    slog::info!(log, "sending error response: {response}");
                    limited_reader
                        .get_mut()
                        .get_mut()
                        .write_all(response.as_bytes())?;
                    break;
                }
            };

            let response = match request {
                Request::Attest(q) => {
                    slog::debug!(log, "qualifying data received: {q:?}");
                    match rot.attest(&q) {
                        Ok(a) => Response::Attest(a),
                        Err(e) => Response::Error(e.to_string()),
                    }
                }
            };

            let mut response = serde_json::to_string(&response)?;
            response.push('\n');

            slog::debug!(log, "sending response: {response}");
            limited_reader
                .get_mut()
                .get_mut()
                .write_all(response.as_bytes())?;
            msg.clear();
        }
    }

    Ok(())
}
