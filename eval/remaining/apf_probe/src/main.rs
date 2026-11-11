use apf_compiler::{frontend, CanonicalPolicy, Projector};
use apf_openshell_projector::OpenShellProjector;
use apf_proto::openshell_sandbox::SandboxPolicy;
use prost::Message;
fn main() {
    let yaml = std::fs::read(std::env::args().nth(1).expect("policy")).unwrap();
    let ir = frontend::parse(&yaml).expect("parse");
    let mut policy = CanonicalPolicy::default();
    policy.sandbox_policies.insert("default".into(), ir);
    let surfaces = OpenShellProjector
        .project(&policy)
        .expect("official projection");
    for s in surfaces {
        if s.kind == "openshell.sandbox.v1" {
            let p = SandboxPolicy::decode(s.bytes.as_slice()).unwrap();
            println!("{:?}", p);
            let fs = p.filesystem.unwrap();
            assert_eq!(fs.read_only, vec!["/usr", "/lib", "/fixtures/alice"]);
            assert!(fs.read_write.is_empty());
            assert!(!fs.include_workdir);
        }
    }
}
