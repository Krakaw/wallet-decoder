// This build script compiles Protobuf definitions from the `proto/` directory
// into Rust code for gRPC client interaction using `tonic-build`.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create the output directory if it doesn't exist
    // This helps avoid issues if the build script runs before Cargo "sees" the dir
    std::fs::create_dir_all("src/utxo/rpc_generated")?;

    let proto_files = &[
        "proto/common.proto",
        "proto/transaction.proto",
        "proto/block.proto",
        "proto/chain_metadata.proto",
        "proto/proof_of_work.proto",
        "proto/core_script.proto",
        "proto/types.proto",
        "proto/network.proto", // network.proto might be problematic if it defines services/rpcs not used
        "proto/base_node.proto",
        "proto/wallet.proto",
    ];
    let proto_include_dirs = &["proto/"];

    tonic_build::configure()
        .build_server(false) // We are only building a client
        .build_client(true)
        .out_dir("src/utxo/rpc_generated") // Output directory for generated files
        .compile(proto_files, proto_include_dirs)?;

    Ok(())
}
