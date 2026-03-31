use std::fs::File;
use std::io::Write;
use clap::{Args, Subcommand};
use tar::Builder;
use aws_config::BehaviorVersion;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_s3::{Client as S3Client, Error as S3Error};
use aws_sdk_s3::operation::put_object::PutObjectOutput;
use aws_sdk_s3::operation::get_object::GetObjectOutput;
use aws_sdk_s3::primitives::{ByteStream, SdkBody};
use aes_gcm::{AeadCore, Aes256Gcm};
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use flate2::GzBuilder;
use flate2::Compression;
use crate::args::GlobalOpts;
use crate::iam_credentials::JdnAwsIamCredentials;
use crate::commands::base::{CredentialConfigData, JSSTCommand};
use crate::util::{GenericErr, BACKUP_BUCKET};
use crate::data_key::VaultDataKey;


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
    #[arg(long, default_value = ".")]
    pub dest: String,
}

#[derive(Args)]
pub struct UploadCommandArgs {
    #[command(subcommand)]
    pub area: BackupAreas
}


#[derive(Subcommand)]
pub enum CliCommandEnum {
    /// Download, decompress, and decrypt archive. Does not extract!
    Download(DownloadCommandArgs),
    /// Gather and upload data to S3
    Upload(UploadCommandArgs)
}

#[derive(Args)]
pub struct BackupCommandStruct {
    #[command(subcommand)]
    pub command: CliCommandEnum,
}

pub struct BackupCommand {
    pub cli: BackupCommandStruct,
    pub opts: GlobalOpts,
}

impl JSSTCommand<BackupCommandStruct> for BackupCommand {
    fn execute(commands: BackupCommandStruct, opts: GlobalOpts) -> GenericErr {
        let cmd = Self { cli: commands, opts };
        Ok(Self::command_wrapper(
            &cmd,
            &cmd.opts,
            Self::run
        )?)
    }
}

impl BackupCommand {
    async fn build_s3_client(creds: &JdnAwsIamCredentials) -> S3Client {
        let region_provider = RegionProviderChain::default_provider().or_else("us-east-1");
        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(region_provider)
            .credentials_provider(creds.to_provider())
            .load()
            .await;
        S3Client::new(&config)
    }

    async fn upload_data_to_s3(data: Vec<u8>, data_key: &str, key: &str, creds: &JdnAwsIamCredentials) -> Result<PutObjectOutput, S3Error> {
        log::info!("Uploading data to S3 - {}", key);
        let client = Self::build_s3_client(creds).await;
        let resp = client.put_object()
            .key(key)
            .bucket(BACKUP_BUCKET)
            .body(ByteStream::new(SdkBody::from(data)))
            .metadata("vault-data-key", data_key)
            .send()
            .await?;
        log::info!("Upload successful");
        Ok(resp)
    }

    async fn retrieve_from_s3(key: &str, version: Option<&str>, creds: &JdnAwsIamCredentials) -> GenericErr<GetObjectOutput> {
        let client = Self::build_s3_client(creds).await;
        let mut req = client.get_object()
            .key(key)
            .bucket(BACKUP_BUCKET);
        match version {
            Some(version) => {
                req = req.version_id(version);
            }
            None => {}
        }
        let resp = req.send().await?;
        log::info!("Retrieved [{}] successfully", key);
        Ok(resp)
    }

    fn run(cmd: &Self, cfg: &CredentialConfigData) -> GenericErr {
        match &cmd.cli.command {
            CliCommandEnum::Upload(c) => Self::match_upload(&cmd, &cfg, &c)?,
            CliCommandEnum::Download(c) => Self::download(&cmd, &cfg, &c)?
        }
        Ok(())
    }

    fn match_upload(&self, cfg: &CredentialConfigData, args: &UploadCommandArgs) -> GenericErr {
        match args.area {
            BackupAreas::LUKS => {todo!()}
            BackupAreas::JDN => {Self::backup_jdn(&self, &cfg)?}
        }
        Ok(())
    }

    fn finish_tar(tar_data: Builder<&mut Vec<u8>>, data_key: &VaultDataKey) -> GenericErr<Vec<u8>> {
        log::info!("Compressing archive");
        let mut gz = GzBuilder::new()
            .write(Vec::new(), Compression::default());
        gz.write_all(&tar_data.into_inner()?)?;
        log::info!("Encrypting archive");
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let tar_data: &[u8] = &gz.finish()?;
        let cipher = Aes256Gcm::new(&data_key.to_aes_256_key()?);
        let encrypted_tar = cipher.encrypt(&nonce, tar_data).unwrap();
        Ok(encrypted_tar)
    }


    fn backup_jdn(&self, cfg: &CredentialConfigData) -> GenericErr {
        // Get Data Key
        let client = Self::login_to_vault(&self.opts, &cfg)?;
        log::info!("Retrieving new encryption data key");
        let data_key = VaultDataKey::retrieve_data_key(&client, "jdn-host-backup", &256)?;

        // Build ZIP File
        log::info!("Adding [{}] to archive", &self.opts.output);
        let mut mem_buf = Vec::new();
        let mut archive = Builder::new(&mut mem_buf);
        for entry in walkdir::WalkDir::new(&self.opts.output) {
            match entry {
                Ok(e) => {
                    log::debug!("Archiving - {:?}", e.path());
                    let e_md = e.metadata().expect("metadata");
                    if e_md.is_dir() {
                        continue
                    }
                    let file_path = e.path().strip_prefix(&self.opts.output)?;
                    let mut e_file = File::open(e.path())?;
                    archive.append_file(file_path, &mut e_file)?;
                },
                Err(e) => {
                    log::warn!("Failed to archive {:?} - {}", e.path(), e);
                }
            }
        }

        // Compressing and Encrypting TAR
        let encrypted_tar = Self::finish_tar(archive, &data_key)?;


        // Upload to S3
        let credentials = JdnAwsIamCredentials::new(
            &client, &cfg.machine_uuid, &self.opts.output, true
        )?;
        let obj_key = format!("{}/jdn-var.tar.encrypted", cfg.machine_uuid);
        let rt  = tokio::runtime::Runtime::new()?;
        let _ = rt.block_on(async {
            let resp = Self::upload_data_to_s3(
                encrypted_tar,
                &data_key.ciphertext,
                &obj_key,
                &credentials
            ).await;
            log::debug!("S3 Upload Response - {:?}", resp);
            resp
        })?;
        Ok(())
    }

    fn download(&self, cfg: &CredentialConfigData, args: &DownloadCommandArgs) -> GenericErr {
        let client = Self::login_to_vault(&self.opts, &cfg)?;
        let creds = JdnAwsIamCredentials::new(
            &client, &cfg.machine_uuid, &self.opts.output, true
        )?;
        let rt  = tokio::runtime::Runtime::new()?;
        let resp = rt.block_on(async {
            let resp = match &args.obj_ver {
                Some(v) => Self::retrieve_from_s3(&args.obj_key, Option::from(v.as_str()), &creds),
                None => Self::retrieve_from_s3(&args.obj_key, None, &creds)
            }.await;
            log::debug!("S3 Retrieve Response - {:?}", resp);
            resp
        })?;
        Ok(())
    }
}