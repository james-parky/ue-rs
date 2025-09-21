use std::borrow::Cow;
use std::cmp::Ordering;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use log::{debug, info};

use reqwest::blocking::Client;
use url::Url;

use crate::{download_and_hash, hash_on_disk};
use omaha::{Sha1Digest, Sha256Digest};
use update_format_crau::delta_update;
use crate::Result;
use crate::error::Error;

#[derive(Debug)]
pub enum PackageStatus {
    ToDownload,
    DownloadIncomplete(usize),
    DownloadFailed,
    BadChecksum,
    Unverified,
    BadSignature,
    Verified,
}

#[derive(Debug)]
pub struct Package<'a> {
    pub url: Url,
    pub name: Cow<'a, str>,
    pub hash_sha256: Option<Sha256Digest>,
    pub hash_sha1: Option<Sha1Digest>,
    pub size: usize,
    pub status: PackageStatus,
}

impl<'a> Package<'a> {
    pub fn from_omaha_package(pkg: &'a omaha::response::Package<'a>, url: Url, status: PackageStatus) -> Self {
        Self {
            url,
            name: Cow::Borrowed(&pkg.name),
            hash_sha256: pkg.hash_sha256,
            hash_sha1: pkg.hash,
            size: pkg.size,
            status,
        }
    }

    // Return Sha256 hash of data in the given path.
    // If max_len is None, a simple read to the end of the file.
    // If max_len is Some, read only until the given length.
    fn hash_on_disk<T: omaha::Hasher>(&mut self, path: &Path, max_len: Option<usize>) -> Result<T::Output> {
        hash_on_disk::<T>(path, max_len)
    }

    fn verify_download(&mut self, path: &Path) -> Result<()> {
        let hash_sha256 = self.hash_on_disk::<omaha::Sha256>(path, None)?;
        let hash_sha1 = self.hash_on_disk::<omaha::Sha1>(path, None)?;

        if self.verify_checksums(hash_sha256, hash_sha1) {
            info!("{}: good hash, will continue without re-download", path.display());
        } else {
            info!("{}: bad hash, will re-download", path.display());
            self.status = PackageStatus::ToDownload;
        }

        Ok(())
    }

    pub fn check_download(&mut self, in_dir: &Path) -> Result<()> {
        let path = in_dir.join(&*self.name);

        let size_on_disk = match path.metadata() {
            Ok(md) => md.len() as usize,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                info!("{} does not exist, skipping existing downloads.", path.display());
                return Ok(());
            }
            Err(err) => return Err(Error::ReadFileMetadata(err)),
        };

        match size_on_disk.cmp(&self.size) {
            Ordering::Less => {
                info!(
                    "{}: have downloaded {}/{} bytes, will resume",
                    path.display(),
                    size_on_disk,
                    self.size
                );

                self.status = PackageStatus::DownloadIncomplete(size_on_disk);
                Ok(())
            }
            Ordering::Equal => {
                info!("{}: download complete, checking hash...", path.display());
                self.verify_download(&path)?;
                Ok(())
            }
            Ordering::Greater => Err(Error::UnexpectedFileSize(self.size, size_on_disk)),
        }
    }

    pub fn download(&mut self, into_dir: &Path, client: &Client) -> Result<()> {
        // FIXME: use _range_start for completing downloads
        let _range_start = match self.status {
            PackageStatus::ToDownload => 0usize,
            PackageStatus::DownloadIncomplete(s) => s,
            _ => return Ok(()),
        };

        info!("downloading {}...", self.url);

        download_and_hash(
            client,
            self.url.clone(),
            &into_dir.join(&*self.name),
            self.hash_sha256,
            self.hash_sha1,
        )
        .inspect_err(|_| self.status = PackageStatus::DownloadFailed)
        .map(|_| self.status = PackageStatus::Unverified)
    }

    fn verify_checksum<H: omaha::Hasher>(exp: H::Output, got: H::Output) -> bool {
        let same = exp == got;

        debug!("    expected {}:   {exp:?}", H::HASH_NAME);
        debug!("    calculated {}: {got:?}", H::HASH_NAME);
        debug!("    {same} match?      {}", H::HASH_NAME);

        same
    }

    fn verify_checksums(&mut self, calculated_sha256: Sha256Digest, calculated_sha1: Sha1Digest) -> bool {
        let sha1_same = self.hash_sha1.is_some_and(|hash| Self::verify_checksum::<omaha::Sha1>(hash, calculated_sha1));
        let sha256_same = self.hash_sha256.is_some_and(|hash| Self::verify_checksum::<omaha::Sha256>(hash, calculated_sha256));

        if !sha1_same || !sha256_same {
            self.status = PackageStatus::BadChecksum;
            false
        } else {
            self.status = PackageStatus::Unverified;
            true
        }
    }

    pub fn verify_signature_on_disk(&mut self, from_path: &Path, pubkey_path: &str) -> Result<PathBuf> {
        let update_file = File::open(from_path).map_err(Error::ReadFileMetadata)?;

        // TODO: Should take an error. This requires removing anyhow dep from
        //      `update-format-crau` as well
        // Read update payload from file, read delta update header from the payload.
        let header = delta_update::read_delta_update_header(&update_file).map_err(|_| Error::ReadDeltaUpdateHeader)?;

        // TODO: Should take an error. This requires removing anyhow dep from
        //      `update-format-crau` as well
        let delta_archive_manifest = delta_update::get_manifest_bytes(&update_file, &header).map_err(|_| Error::ReadDeltaUpdateHeader)?;

        // TODO: Should take an error. This requires removing anyhow dep from
        //      `update-format-crau` as well
        // Extract signature from header.
        let signature_bytes = delta_update::get_signatures_bytes(&update_file, &header, &mut delta_archive_manifest).map_err(|_| Error::GetSignatureBytes)?;

        // tmp dir == "/var/tmp/outdir/.tmp"
        let tmp_dir_path = from_path.parent().ok_or(Error::GetParentDir)?.parent().ok_or(Error::GetParentDir)?.join(".tmp");
        let temp_dir = tmp_dir_path.as_path();
        let data_blob_path = temp_dir.join("ue_data_blobs");

        // TODO: Should take an error. This requires removing anyhow dep from
        //      `update-format-crau` as well
        // Get length of header and data, including header and manifest.
        let header_data_length = delta_update::get_header_data_length(&header, &delta_archive_manifest).map_err(|_| Error::GetHeaderLength)?;
        let header_hash = self.hash_on_disk::<omaha::Sha256>(from_path, Some(header_data_length))?;

        // TODO: Should take an error. This requires removing anyhow dep from
        //      `update-format-crau` as well
        // Extract data blobs into a file, data_blob_path.
        delta_update::get_data_blobs(&update_file, &header, &delta_archive_manifest, data_blob_path.as_path()).map_err(|_| Error::GetDataBlobsPath)?;

        // Check for hash of data blobs with new_partition_info hash.
        let pinfo_hash = &delta_archive_manifest.new_partition_info.hash.as_ref().ok_or(Error::MissingNewPartitionInfoHash)?;

        let data_hash = self.hash_on_disk::<omaha::Sha256>(data_blob_path.as_path(), None)?;
        if data_hash != pinfo_hash.as_slice() {
            return Err(Error::DataAndPartitionInfoHashMismatch(data_hash, pinfo_hash.to_vec()));
        }

        // TODO: why are we ignoring return value here anyway?
        // Parse signature data from sig blobs, data blobs, public key, and verify.
        delta_update::parse_signature_data(&signature_bytes, &header_hash, pubkey_path)
            .map_err(|_| {
                self.status = PackageStatus::BadSignature;
                // TODO: Should take an error. This requires removing anyhow dep from
                //      `update-format-crau` as well
                Error::ParseSignature(signature_bytes, header_hash, pubkey_path.to_string())
            })
            .map(|_| {
                println!("Parsed and verified signature data from file {from_path:?}");
                self.status = PackageStatus::Verified;
                data_blob_path
            })
    }
}
