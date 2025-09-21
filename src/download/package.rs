use std::borrow::Cow;
use std::fs::File;
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

    #[rustfmt::skip]
    // Return Sha256 hash of data in the given path.
    // If maxlen is None, a simple read to the end of the file.
    // If maxlen is Some, read only until the given length.
    fn hash_on_disk<T: omaha::Hasher>(&mut self, path: &Path, maxlen: Option<usize>) -> Result<T::Output> {
        hash_on_disk::<T>(path, maxlen)
    }

    #[rustfmt::skip]
    pub fn check_download(&mut self, in_dir: &Path) -> Result<()> {
        let path = in_dir.join(&*self.name);

        if !path.exists() {
            // skip checking for existing downloads
            info!("{} does not exist, skipping existing downloads.", path.display());
            return Ok(());
        }

        let md = path.metadata().map_err(Error::ReadFileMetadata)?;

        let size_on_disk = md.len() as usize;
        let expected_size = self.size;

        if size_on_disk < expected_size {
            info!("{}: have downloaded {}/{} bytes, will resume", path.display(), size_on_disk, expected_size);

            self.status = PackageStatus::DownloadIncomplete(size_on_disk);
            return Ok(());
        }

        if size_on_disk == expected_size {
            info!("{}: download complete, checking hash...", path.display());
            let hash_sha256 = self.hash_on_disk::<omaha::Sha256>(&path, None)?;
            let hash_sha1 = self.hash_on_disk::<omaha::Sha1>(&path, None)?;
            if self.verify_checksum(hash_sha256, hash_sha1) {
                info!("{}: good hash, will continue without re-download", path.display());
            } else {
                info!("{}: bad hash, will re-download", path.display());
                self.status = PackageStatus::ToDownload;
            }
        }

        Ok(())
    }

    pub fn download(&mut self, into_dir: &Path, client: &Client) -> Result<()> {
        // FIXME: use _range_start for completing downloads
        let _range_start = match self.status {
            PackageStatus::ToDownload => 0usize,
            PackageStatus::DownloadIncomplete(s) => s,
            _ => return Ok(()),
        };

        info!("downloading {}...", self.url);

        let path = into_dir.join(&*self.name);
        match download_and_hash(
            client,
            self.url.clone(),
            &path,
            self.hash_sha256.clone(),
            self.hash_sha1.clone(),
        ) {
            Err(err) => {
                self.status = PackageStatus::DownloadFailed;
                Err(err)
            }
            _ => {
                self.status = PackageStatus::Unverified;
                Ok(())
            }
        }
    }

    fn verify_checksum(&mut self, calculated_sha256: Sha256Digest, calculated_sha1: Sha1Digest) -> bool {
        debug!("    expected sha256:   {:?}", self.hash_sha256);
        debug!("    calculated sha256: {calculated_sha256:?}");
        debug!("    sha256 match?      {}", self.hash_sha256 == Some(calculated_sha256.clone()));
        debug!("    expected sha1:   {:?}", self.hash_sha1);
        debug!("    calculated sha1: {calculated_sha1:?}");
        debug!("    sha1 match?      {}", self.hash_sha1 == Some(calculated_sha1.clone()));

        if self.hash_sha256.is_some() && self.hash_sha256 != Some(calculated_sha256.clone()) || self.hash_sha1.is_some() && self.hash_sha1 != Some(calculated_sha1.clone()) {
            self.status = PackageStatus::BadChecksum;
            false
        } else {
            self.status = PackageStatus::Unverified;
            true
        }
    }

    pub fn verify_signature_on_disk(&mut self, from_path: &Path, pubkey_path: &str) -> Result<PathBuf> {
        let upfile = File::open(from_path).map_err(Error::ReadFileMetadata)?;

        // TODO: Should take an error. This requires removing anyhow dep from
        //      `update-format-crau` as well
        // Read update payload from file, read delta update header from the payload.
        let header = delta_update::read_delta_update_header(&upfile).map_err(|_| Error::ReadDeltaUpdateHeader)?;

        // TODO: Should take an error. This requires removing anyhow dep from
        //      `update-format-crau` as well
        let mut delta_archive_manifest = delta_update::get_manifest_bytes(&upfile, &header).map_err(|_| Error::ReadDeltaUpdateHeader)?;

        // TODO: Should take an error. This requires removing anyhow dep from
        //      `update-format-crau` as well
        // Extract signature from header.
        let sigbytes = delta_update::get_signatures_bytes(&upfile, &header, &mut delta_archive_manifest).map_err(|_| Error::GetSignatureBytes)?;

        // tmp dir == "/var/tmp/outdir/.tmp"
        let tmpdirpathbuf = from_path.parent().ok_or(Error::GetParentDir)?.parent().ok_or(Error::GetParentDir)?.join(".tmp");
        let tmpdir = tmpdirpathbuf.as_path();
        let datablobspath = tmpdir.join("ue_data_blobs");

        // TODO: Should take an error. This requires removing anyhow dep from
        //      `update-format-crau` as well
        // Get length of header and data, including header and manifest.
        let header_data_length = delta_update::get_header_data_length(&header, &delta_archive_manifest).map_err(|_| Error::GetHeaderLength)?;
        let hdhash = self.hash_on_disk::<omaha::Sha256>(from_path, Some(header_data_length))?;
        let hdhashvec: Vec<u8> = hdhash.clone().into();

        // TODO: Should take an error. This requires removing anyhow dep from
        //      `update-format-crau` as well
        // Extract data blobs into a file, datablobspath.
        delta_update::get_data_blobs(&upfile, &header, &delta_archive_manifest, datablobspath.as_path()).map_err(|_| Error::GetDataBlobsPath)?;

        // Check for hash of data blobs with new_partition_info hash.
        let pinfo_hash = &delta_archive_manifest.new_partition_info.hash.as_ref().ok_or(Error::MissingNewPartitionInfoHash)?;

        let datahash = self.hash_on_disk::<omaha::Sha256>(datablobspath.as_path(), None)?;
        if datahash != pinfo_hash.as_slice() {
            return Err(Error::DataAndPartitionInfoHashMismatch(datahash, pinfo_hash.to_vec()));
        }

        // Parse signature data from sig blobs, data blobs, public key, and verify.
        match delta_update::parse_signature_data(&sigbytes, hdhashvec.as_slice(), pubkey_path) {
            Ok(_) => {
                println!("Parsed and verified signature data from file {from_path:?}");
                self.status = PackageStatus::Verified;
                Ok(datablobspath)
            }
            Err(_) => {
                self.status = PackageStatus::BadSignature;
                // TODO: Should take an error. This requires removing anyhow dep from
                //      `update-format-crau` as well
                Err(Error::ParseSignature(sigbytes, hdhash, pubkey_path.to_string()))
            }
        }
    }
}
