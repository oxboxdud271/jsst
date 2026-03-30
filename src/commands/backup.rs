use clap::{Args, Subcommand};
use zip::{AesMode, ZipWriter};
use std::io::Cursor;
use aws_config::BehaviorVersion;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_s3::{Client, Error as S3Error};
use aws_sdk_s3::operation::put_object::PutObjectOutput;
use aws_sdk_s3::primitives::{ByteStream, SdkBody};
use zip::write::SimpleFileOptions;
use crate::args::GlobalOpts;
use crate::iam_credentials::JdnAwsIamCredentials;
use crate::commands::base::{CredentialConfigData, JSSTCommand};
use crate::util::{retrieve_data_key_from_vault, GenericErr};

#[derive(Subcommand)]
pub enum CliCommandEnum {
    /// Backup JDN Directory
    JDN,
    /// Backup LUKS Header
    LUKS
}

#[derive(Args)]
pub struct BackupCommandStruct {
    #[command(subcommand)]
    pub command: CliCommandEnum,

    #[arg(long, default_value = "server-admin")]
    username: String,
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
            |cmd, cfg| {
                match &cmd.cli.command {
                    CliCommandEnum::JDN => Self::backup_jdn(&cmd, &cfg),
                    CliCommandEnum::LUKS => todo!()
                }
            }
        )?)
    }
}

impl BackupCommand {
    async fn upload_data_to_s3(data: Vec<u8>, data_key: &str, key: &str, creds: &JdnAwsIamCredentials) -> Result<PutObjectOutput, S3Error> {
        log::info!("Uploading data to S3 - {}", key);
        let region_provider = RegionProviderChain::default_provider().or_else("us-east-1");
        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(region_provider)
            .credentials_provider(creds.to_provider())
            .load()
            .await;

        let client = Client::new(&config);
        Ok(client.put_object()
            .key(key)
            .bucket("jdn-host-backups-048780619790-us-east-1-an")
            .body(ByteStream::new(SdkBody::from(data)))
            .metadata("vault-data-key", data_key)
            .send()
            .await?
        )
    }

    fn default_options() -> SimpleFileOptions {
        SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Bzip2)
    }


    fn backup_jdn(&self, cfg: &CredentialConfigData) -> GenericErr {
        // Get Data Key
        let client = Self::login_to_vault(&self.opts, &cfg)?;
        let data_key = retrieve_data_key_from_vault(&client, "jdn-host-backup", &256)?;

        // Build ZIP File
        let mut cursor = Cursor::new(Vec::new());
        let mut archive = ZipWriter::new(&mut cursor);
        let options = Self::default_options();
        archive.add_directory_from_path(&self.opts.output, options)?;
        archive.finish()?;

        // Upload to S3
        let credentials = JdnAwsIamCredentials::new(
            &client, &cfg.machine_uuid, &self.opts.output, true
        )?;
        let obj_key = format!("{}/jdn-var.zip", cfg.machine_uuid);
        let rt  = tokio::runtime::Runtime::new()?;
        let _ = rt.block_on(async {
            let resp = Self::upload_data_to_s3(
                cursor.into_inner(),
                &data_key.ciphertext,
                &obj_key,
                &credentials
            ).await;
            log::debug!("S3 Upload Response - {:?}", resp);
        });
        Ok(())
    }
}