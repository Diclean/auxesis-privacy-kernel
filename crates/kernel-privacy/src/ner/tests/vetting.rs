//! Model-directory vetting: symlinks, missing files and the home bound.

use crate::safetext::name_spotter_installed;

use super::super::local::{install_local_model, vet_model_dir, Vetting};

#[test]
fn a_symlinked_model_file_is_refused_and_mounts_nothing() {
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().join("models").join("gliner2-pii");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(home.path().join("elsewhere.onnx"), b"x").unwrap();
    std::os::unix::fs::symlink(home.path().join("elsewhere.onnx"), dir.join("model.onnx")).unwrap();
    std::fs::write(dir.join("tokenizer.json"), b"{}").unwrap();
    assert_eq!(
        vet_model_dir(home.path(), &dir).unwrap_err(),
        Vetting::Refused
    );
    assert!(!install_local_model(home.path(), &dir));
    assert!(!name_spotter_installed());
}

#[test]
fn a_model_dir_outside_the_home_or_behind_a_symlink_is_refused() {
    let home = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    for file in ["model.onnx", "tokenizer.json"] {
        std::fs::write(elsewhere.path().join(file), b"x").unwrap();
    }
    assert_eq!(
        vet_model_dir(home.path(), elsewhere.path()).unwrap_err(),
        Vetting::Refused
    );
    std::fs::create_dir_all(home.path().join("models")).unwrap();
    let link = home.path().join("models").join("gliner2-pii");
    std::os::unix::fs::symlink(elsewhere.path(), &link).unwrap();
    assert_eq!(
        vet_model_dir(home.path(), &link).unwrap_err(),
        Vetting::Refused
    );
}

#[test]
fn plain_files_inside_the_home_are_accepted_and_missing_files_are_absent() {
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().join("models").join("gliner2-pii");
    std::fs::create_dir_all(&dir).unwrap();
    assert_eq!(
        vet_model_dir(home.path(), &dir).unwrap_err(),
        Vetting::Absent
    );
    std::fs::write(dir.join("model_int8.onnx"), b"x").unwrap();
    std::fs::write(dir.join("tokenizer.json"), b"{}").unwrap();
    let config = vet_model_dir(home.path(), &dir).unwrap();
    assert_eq!(config.onnx_file, "model_int8.onnx");
}
