// This build script compiles Protobuf definitions from the `proto/` directory
// into Rust code for gRPC client interaction using `tonic-build`.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create the output directory if it doesn't exist
    // This helps avoid issues if the build script runs before Cargo "sees" the dir
    std::fs::create_dir_all("src/utxo/rpc_generated")?;

    let proto_files = &[
        "proto/base_node.proto",
        "proto/block.proto",
        "proto/network.proto",
        "proto/p2pool.proto",
        "proto/sidechain_types.proto",
        "proto/transaction.proto",
        "proto/types.proto",
        "proto/validator_node.proto",
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
