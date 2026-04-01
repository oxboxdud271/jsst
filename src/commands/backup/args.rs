use clap::{Args, Subcommand};

#[derive(Subcommand)]
pub enum BackupAreas {
    /// JDN Directory
    JDN,
    /// LUKS Header
    LUKS
}


#[derive(Args)]
pub struct DownloadCommandArgs {
    /// S3 Object key
    #[arg(long)]
    pub obj_key: String,

    /// S3 Object version
    #[arg(long)]
    pub obj_ver: Option<String>,

    /// Destination
    #[arg(long, default_value = "./output.tar.gz")]
    pub dest: String,
}

#[derive(Args)]
pub struct UploadCommandArgs {
    #[command(subcommand)]
    pub area: BackupAreas
}

#[derive(Args)]
pub struct DecryptCommandArgs {
    /// Encrypted object
    #[arg(long)]
    pub src: String,

    /// Decrypted object destination
    #[arg(long)]
    pub dest: String,

    /// Vault cipher used to encrypt object
    #[arg(long)]
    pub cipher: String,

    /// Nonce in base64
    #[arg(long)]
    pub nonce: String
}


#[derive(Subcommand)]
pub enum CliCommandEnum {
    /// Download and decrypt archive. Does not extract!
    Download(DownloadCommandArgs),
    /// Gather and upload data to S3
    Upload(UploadCommandArgs),
    /// Decrypt an offline backup
    Decrypt(DecryptCommandArgs),
}

#[derive(Args)]
pub struct BackupCommandStruct {
    #[command(subcommand)]
    pub command: CliCommandEnum,
}