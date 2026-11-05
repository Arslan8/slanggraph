use apf_compiler::{frontend, CanonicalPolicy, Projector};
use apf_openshell_projector::OpenShellProjector;
use apf_proto::openshell_sandbox::SandboxPolicy;
use prost::Message;
use serde_json::{json, Map, Value};

fn main() {
    let bytes = std::fs::read(std::env::args().nth(1).expect("input policy")).unwrap();
    let mut policy = CanonicalPolicy::default();
    policy
        .sandbox_policies
        .insert("default".into(), frontend::parse(&bytes).unwrap());
    let surfaces = OpenShellProjector.project(&policy).unwrap();
    let surface = surfaces
        .iter()
        .find(|s| s.kind == "openshell.sandbox.v1")
        .unwrap();
    let projected = SandboxPolicy::decode(surface.bytes.as_slice()).unwrap();
    assert!(projected.network_middlewares.is_empty());
    let network_policies = projected
        .network_policies
        .into_iter()
        .map(|(key, rule)| {
            let endpoints = rule
                .endpoints
                .into_iter()
                .map(|endpoint| {
                    json!({
                        "host": endpoint.host,
                        "port": endpoint.port,
                        "ports": endpoint.ports,
                        "protocol": endpoint.protocol,
                        "allowed_ips": endpoint.allowed_ips,
                    })
                })
                .collect::<Vec<_>>();
            let binaries = rule
                .binaries
                .into_iter()
                .map(|binary| json!({"path": binary.path}))
                .collect::<Vec<_>>();
            (
                key,
                json!({
                    "name": rule.name,
                    "endpoints": endpoints,
                    "binaries": binaries,
                }),
            )
        })
        .collect::<Map<String, Value>>();
    let fs = projected.filesystem.unwrap();
    let landlock = projected.landlock.unwrap();
    let process = projected.process.unwrap();
    println!(
        "{}",
        json!({"version":projected.version,
        "filesystem_policy":{"include_workdir":fs.include_workdir,"read_only":fs.read_only,"read_write":fs.read_write},
        "landlock":{"compatibility":landlock.compatibility},
        "process":{"run_as_user":process.run_as_user,"run_as_group":process.run_as_group},
        "network_policies":network_policies})
    );
}
