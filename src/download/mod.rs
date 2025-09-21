pub mod package;

use std::borrow::Cow;
use std::io::{BufReader, Read};
use std::ffi::OsStr;
use std::fs::File;
use std::fs;
use std::path::Path;
use std::time::Duration;

use globset::GlobSet;
use hard_xml::XmlRead;
use log::{debug, info, warn};
use reqwest::{blocking::Client, redirect::Policy};
use url::Url;

use crate::error::Error;
use crate::Result;
use crate::{Package, PackageStatus};
use omaha::{Sha1Digest, Sha256Digest};

pub const TARGET_FILENAME_DEFAULT: &str = "oem-azure.gz";
pub const PAYLOAD_URL_DEFAULT: &str = "https://update.release.flatcar-linux.net/amd64-usr/current/oem-azure.gz";

pub struct DownloadResult {
    pub hash_sha256: Sha256Digest,
    pub hash_sha1: Sha1Digest,
    pub data: File,
}

pub fn hash_on_disk<T: omaha::Hasher>(path: &Path, max_len: Option<usize>) -> Result<T::Output> {
    const CHUNK_LEN: usize = 10 * 1024 * 1024; // 10MB

    let file = File::open(path).map_err(Error::OpenFile)?;
    let file_len = file.metadata().map_err(Error::ReadFileMetadata)?.len() as usize;

    let mut hasher = T::new();
    let mut reader = BufReader::new(file);
    let mut buf = vec![0u8; CHUNK_LEN];
    let mut remaining_bytes_to_read = max_len.map_or(file_len, |len| len.min(file_len));

    while remaining_bytes_to_read > 0 {
        if remaining_bytes_to_read < CHUNK_LEN {
            // Last and submaximal chunk to read, shrink the buffer for it
            buf.truncate(remaining_bytes_to_read);
        }

        reader.read_exact(&mut buf).map_err(|err| Error::ReadFileChunk(CHUNK_LEN, err))?;
        remaining_bytes_to_read -= buf.len();
        hasher.update(&buf);
    }

    Ok(hasher.finalize())
}

fn do_download_and_hash<U>(client: &Client, url: U, path: &Path, expected_sha256: Option<Sha256Digest>, expected_sha1: Option<Sha1Digest>) -> Result<DownloadResult>
where
    U: reqwest::IntoUrl + Clone,
    Url: From<U>,
{
    let mut res = client.get(url.clone()).send().map_err(|err| Error::ClientSend(url.as_str().to_string(), err))?;

    // Redirect was already handled at this point, so there is no need to touch
    // response or url again. Simply print info and continue.
    if *res.url() != url.into() {
        info!("redirected to URL {:?}", res.url());
    }

    // Return immediately on download failure on the client side.
    match res.status() {
        sc if !sc.is_success() => return Err(Error::FailedToFetch(sc)),
        _ => {}
    }

    let calculated_sha256 = hash_on_disk::<omaha::Sha256>(path, None)?;
    let calculated_sha1 = hash_on_disk::<omaha::Sha1>(path, None)?;

    debug!("    expected sha256:   {expected_sha256:x?}");
    debug!("    calculated sha256: {calculated_sha256:x?}");
    debug!("    sha256 match?      {}", expected_sha256 == Some(calculated_sha256));
    debug!("    expected sha1:   {expected_sha1:x?}");
    debug!("    calculated sha1: {calculated_sha1:x?}");
    debug!("    sha1 match?      {}", expected_sha1 == Some(calculated_sha1));

    if let Some(exp) = expected_sha256.filter(|&sha256| sha256 != calculated_sha256) {
        return Err(Error::Sha256ChecksumMismatch(exp, calculated_sha256));
    }

    if let Some(exp) = expected_sha1.filter(|&sha1| sha1 != calculated_sha1) {
        return Err(Error::Sha1ChecksumMismatch(exp, calculated_sha1));
    }

    let mut file = File::create(path).map_err(Error::CreateFile)?;
    res.copy_to(&mut file).map_err(Error::WriteResponse)?;
    Ok(DownloadResult {
        hash_sha256: calculated_sha256,
        hash_sha1: calculated_sha1,
        data: file,
    })
}

pub fn download_and_hash<U>(client: &Client, url: U, path: &Path, expected_sha256: Option<Sha256Digest>, expected_sha1: Option<Sha1Digest>) -> Result<DownloadResult>
where
    U: reqwest::IntoUrl + Clone,
    Url: From<U>,
{
    const MAX_DOWNLOAD_RETRY: u32 = 20;

    crate::retry_loop(
        || do_download_and_hash(client, url.clone(), path, expected_sha256, expected_sha1),
        MAX_DOWNLOAD_RETRY,
    )
}

fn get_pkgs_to_download<'a>(resp: &'a omaha::Response, glob_set: &GlobSet) -> Result<Vec<Package<'a>>> {
    Ok(resp
        .apps
        .iter()
        .filter_map(|app| {
            let url_base = app.update_check.urls.first()?;

            Some(
                app.update_check
                    .manifest
                    .packages
                    .iter()
                    .filter(|pkg| glob_set.is_match(pkg.name.as_ref()))
                    .filter(|pkg| pkg.hash.is_some() || pkg.hash_sha256.is_some())
                    .filter_map(|pkg| url_base.join(&pkg.name).ok().map(|url| Package::from_omaha_package(pkg, url, PackageStatus::ToDownload))),
            )
        })
        .flatten()
        .collect())
}

// Read data from remote URL into File
fn fetch_url_to_file<'a, U>(path: &'a Path, input_url: U, client: &'a Client) -> Result<Package<'a>>
where
    U: reqwest::IntoUrl + From<U> + Clone + std::fmt::Debug,
    Url: From<U>,
{
    const FAKE_PACKAGE_FILENAME: &str = "fakepackage";

    let r = download_and_hash(client, input_url.clone(), path, None, None)?;

    Ok(Package {
        name: Cow::Borrowed(path.file_name().and_then(|f| f.to_str()).unwrap_or(FAKE_PACKAGE_FILENAME)),
        hash_sha256: Some(r.hash_sha256),
        hash_sha1: Some(r.hash_sha1),
        size: r.data.metadata().map_err(Error::ReadFileMetadata)?.len() as usize,
        url: input_url.into(),
        status: PackageStatus::Unverified,
    })
}

fn do_download_verify(pkg: &mut Package<'_>, output_filename: Option<String>, output_dir: &Path, unverified_dir: &Path, pubkey_file: &str, client: &Client) -> Result<()> {
    pkg.check_download(unverified_dir)?;
    pkg.download(unverified_dir, client)?;

    // Unverified payload is stored in e.g. "output_dir/.unverified/oem.gz".
    // Verified payload is stored in e.g. "output_dir/oem.raw".
    let pkg_unverified = unverified_dir.join(&*pkg.name);
    let pkg_verified = output_dir.join(output_filename.as_ref().map(OsStr::new).unwrap_or(pkg_unverified.with_extension("raw").file_name().unwrap_or_default()));

    let data_blob_path = pkg.verify_signature_on_disk(&pkg_unverified, pubkey_file)?;

    // Write extracted data into the final data.
    debug!("data blobs written into file {pkg_verified:?}");
    fs::rename(data_blob_path, pkg_verified).map_err(Error::RenameFile)
}

pub struct DownloadVerify {
    output_dir: String,
    target_filename: Option<String>,
    input_xml: String,
    pubkey_file: String,
    payload_url: Option<String>,
    take_first_match: bool,
    glob_set: GlobSet,
}

impl DownloadVerify {
    pub fn new(param_output_dir: String, param_pubkey_file: String, param_take_first_match: bool, param_glob_set: GlobSet) -> Self {
        Self {
            output_dir: param_output_dir,
            target_filename: None,
            input_xml: "".to_string(),
            pubkey_file: param_pubkey_file,
            payload_url: None,
            take_first_match: param_take_first_match,
            glob_set: param_glob_set,
        }
    }

    pub fn target_filename(mut self, param_target_filename: String) -> Self {
        self.target_filename = Some(param_target_filename);
        self
    }

    pub fn input_xml(mut self, param_input_xml: String) -> Self {
        self.input_xml = param_input_xml;
        self
    }

    pub fn payload_url(mut self, param_payload_url: String) -> Self {
        self.payload_url = Some(param_payload_url);
        self
    }

    pub fn run(&self) -> Result<()> {
        const UNVERIFIED_SUFFIX: &str = ".unverified";
        const TMP_SUFFIX: &str = ".tmp";
        const DOWNLOAD_TIMEOUT: u64 = 3600;
        const HTTP_CONN_TIMEOUT: u64 = 20;

        let output_dir = Path::new(&self.output_dir);
        let unverified_dir = output_dir.join(UNVERIFIED_SUFFIX);
        let temp_dir = output_dir.join(TMP_SUFFIX);
        fs::create_dir_all(&unverified_dir).map_err(Error::CreateDirAll)?;
        fs::create_dir_all(&temp_dir).map_err(Error::CreateDirAll)?;

        // The default policy of reqwest Client supports max 10 attempts on HTTP redirect.
        let client = Client::builder()
            .tcp_keepalive(Duration::from_secs(HTTP_CONN_TIMEOUT))
            .connect_timeout(Duration::from_secs(HTTP_CONN_TIMEOUT))
            .timeout(Duration::from_secs(DOWNLOAD_TIMEOUT))
            .redirect(Policy::default())
            .build()
            .map_err(Error::BuildClient)?;

        if self.payload_url.is_some() {
            let url = self.payload_url.clone().unwrap();
            let u = Url::parse(&url).map_err(Error::ParseUrl)?;
            let file_name = u.path_segments().ok_or(Error::GetPathSegments(u.clone()))?.next_back().ok_or(Error::GetPathSegments(u.clone()))?;
            let mut pkg_fake: Package;

            let temp_payload_path = unverified_dir.join(file_name);
            pkg_fake = fetch_url_to_file(&temp_payload_path, u, &client)?;
            do_download_verify(
                &mut pkg_fake,
                self.target_filename.clone(),
                output_dir,
                unverified_dir.as_path(),
                self.pubkey_file.as_str(),
                &client,
            )?;

            // Verify only a fake package, early exit and skip the rest.
            return Ok(());
        }

        let resp = omaha::Response::from_str(&self.input_xml).map_err(Error::ParseXmlResponse)?;

        let mut pkgs_to_dl = get_pkgs_to_download(&resp, &self.glob_set)?;

        debug!("pkgs:\n\t{pkgs_to_dl:#?}\n");

        for pkg in pkgs_to_dl.iter_mut() {
            do_download_verify(
                pkg,
                self.target_filename.clone(),
                output_dir,
                unverified_dir.as_path(),
                self.pubkey_file.as_str(),
                &client,
            )?;
            if self.take_first_match {
                break;
            }
        }

        // clean up data
        fs::remove_dir_all(temp_dir).map_err(Error::RemoveDirAll)
    }
}
