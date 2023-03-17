fn nargo_cmd() -> std::process::Command {
    std::process::Command::new("nargo")
}

fn nargo_execute(test_program_dir: &std::path::PathBuf) -> std::io::Result<std::process::Output> {
    nargo_cmd()
        .current_dir(test_program_dir)
        .arg("execute")
        // .arg("[WITNESS_NAME]")
        .output()
}

fn nargo_test(test_program_dir: &std::path::PathBuf) -> std::io::Result<std::process::Output> {
    nargo_cmd()
        .current_dir(test_program_dir)
        .arg("test")
        .output()
}

fn nargo_check(test_program_dir: &std::path::PathBuf) -> std::io::Result<std::process::Output> {
    nargo_cmd()
        .current_dir(test_program_dir)
        .arg("check")
        .output()
}

fn nargo_gates(test_program_dir: &std::path::PathBuf) -> std::io::Result<std::process::Output> {
    nargo_cmd()
        .current_dir(test_program_dir)
        .arg("gates")
        .output()
}

fn nargo_compile(test_program_dir: &std::path::PathBuf) -> std::io::Result<std::process::Output> {
    nargo_cmd()
        .current_dir(test_program_dir)
        .arg("compile")
        .arg("my_test_circuit")
        .output()
}

fn nargo_prove(test_program_dir: &std::path::PathBuf) -> std::io::Result<std::process::Output> {
    nargo_cmd()
        .current_dir(test_program_dir)
        .arg("prove")
        .arg("my_test_proof")
        .arg("my_test_circuit")
        .output()
}

fn nargo_verify(test_program_dir: &std::path::PathBuf) -> std::io::Result<std::process::Output> {
    nargo_cmd()
        .current_dir(test_program_dir)
        .arg("verify")
        .arg("my_test_proof")
        .arg("my_test_circuit")
        .output()
}

fn test_program_dir_path(dir_name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(format!("tests/test_programs/{dir_name}"))
}

fn assert_nargo_cmd_works(cmd_name: &str, test_test_program_dir: &std::path::PathBuf) {
    let cmd_output = match cmd_name {
        "check" => nargo_check(test_test_program_dir),
        "contract" => todo!(),
        "compile" => nargo_compile(test_test_program_dir),
        "new" => panic!("This cmd doesn't depend on the backend"),
        "execute" => nargo_execute(test_test_program_dir),
        "prove" => nargo_prove(test_test_program_dir),
        "verify" => nargo_verify(test_test_program_dir),
        "test" => nargo_test(test_test_program_dir),
        "gates" => nargo_gates(test_test_program_dir),
        e => panic!("{e} is not a valid nargo cmd"),
    }
    .unwrap();

    assert!(
        cmd_output.status.success(),
        "stderr(nargo {cmd_name}) in {}: {}",
        test_test_program_dir.display(),
        String::from_utf8(cmd_output.stderr).unwrap()
    );
}

fn install_nargo() {
    std::process::Command::new("make")
        .arg("-C")
        .arg(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .to_str()
                .unwrap(),
        )
        .arg("nargo")
        .output()
        .unwrap();
}

#[test]
fn test_integration() {
    // TODO: Refactor this.
    let test_dirs_names = vec![
        "array_neq",
        "assign_ex",
        "bool_not",
        "bool_or",
        "cast_bool",
        "comptime_recursion_regression",
        "generics",
        "global_consts",
        "main_bool_arg",
        "modules",
        "modules_more",
        "pred_eq",
        "priv_x_eq_pub_y",
        "priv_x_neq_pub_y",
        "struct",
        "struct_inputs",
    ];
    let test_program_dirs: Vec<std::path::PathBuf> = test_dirs_names
        .into_iter()
        .map(test_program_dir_path)
        .collect();

    // Ensure our nargo's fork is being used here.
    install_nargo();

    for test_program in test_program_dirs {
        assert_nargo_cmd_works("check", &test_program);
        assert_nargo_cmd_works("compile", &test_program);
        assert_nargo_cmd_works("execute", &test_program);
        assert_nargo_cmd_works("prove", &test_program);
        assert_nargo_cmd_works("verify", &test_program);
        assert_nargo_cmd_works("test", &test_program);
        assert_nargo_cmd_works("gates", &test_program);
    }
}
