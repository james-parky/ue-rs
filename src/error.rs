use std::fmt::Display;
use url::Url;

#[derive(Debug)]
pub enum Error {
    OpenFile(std::io::Error),
    ReadFileMetadata(std::io::Error),
    ReadFileChunk(usize, std::io::Error),
    ClientSend(String, reqwest::Error),
    FailedToFetch(reqwest::StatusCode),
    CreateFile(std::io::Error),
    WriteResponse(reqwest::Error),
    Sha256ChecksumMismatch([u8; 32], [u8; 32]),
    Sha1ChecksumMismatch([u8; 20], [u8; 20]),
    // TODO: Should take an error. This requires removing anyhow dep from
    //      `update-format-crau` as well
    ReadDeltaUpdateHeader,
    // TODO: Should take an error. This requires removing anyhow dep from
    //      `update-format-crau` as well
    GetManifestBytes,
    // TODO: Should take an error. This requires removing anyhow dep from
    //      `update-format-crau` as well
    GetSignatureBytes,
    GetParentDir,
    // TODO: Should take an error. This requires removing anyhow dep from
    //      `update-format-crau` as well
    GetHeaderLength,
    // TODO: Should take an error. This requires removing anyhow dep from
    //      `update-format-crau` as well
    GetDataBlobsPath,
    MissingNewPartitionInfoHash,
    DataAndPartitionInfoHashMismatch([u8; 32], Vec<u8>),
    // TODO: Should take an error. This requires removing anyhow dep from
    //      `update-format-crau` as well
    ParseSignature(Box<[u8]>, [u8; 32], String),
    RenameFile(std::io::Error),
    CreateDirAll(std::io::Error),
    BuildClient(reqwest::Error),
    ParseUrl(url::ParseError),
    GetPathSegments(Url),
    ParseXmlResponse(hard_xml::XmlError),
    RemoveDirAll(std::io::Error),
}

impl std::error::Error for Error {}

impl<'a> Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::OpenFile(err) => write!(f, "failed to open file: {err:?}"),
            Error::ReadFileMetadata(err) => write!(f, "failed to get metadata of file: {err:?}"),
            Error::ReadFileChunk(len, err) => write!(f, "failed to read_exact(chunklen {len}): {err:?}"),
            Error::ClientSend(url, err) => write!(f, "client failed to send request to {url}: {err:?}"),
            Error::FailedToFetch(sc) => write!(f, "failed to fetch: {sc:?}"),
            Error::CreateFile(err) => write!(f, "failed to create file: {err:?}"),
            Error::WriteResponse(err) => write!(f, "failed to write response body to file: {err:?}"),
            Error::Sha256ChecksumMismatch(a, b) => write!(
                f,
                "sha256 checksum mismatch, expected {}, got {}",
                String::from_utf8_lossy(a),
                String::from_utf8_lossy(b)
            ),
            Error::Sha1ChecksumMismatch(a, b) => write!(
                f,
                "sha256 checksum mismatch, expected {}, got {}",
                String::from_utf8_lossy(a),
                String::from_utf8_lossy(b)
            ),
            Error::ReadDeltaUpdateHeader => f.write_str("failed to read delta update header"),
            Error::GetManifestBytes => f.write_str("failed to get manifest bytes"),
            Error::GetSignatureBytes => f.write_str("failed to get signature bytes"),
            Error::GetParentDir => f.write_str("failed to get parent dir"),
            Error::GetHeaderLength => f.write_str("failed to get header length"),
            Error::GetDataBlobsPath => f.write_str("failed to get data blobs path"),
            Error::MissingNewPartitionInfoHash => f.write_str("missing new_partition_info hash"),
            Error::DataAndPartitionInfoHashMismatch(a, b) => write!(
                f,
                "data and partition info hash mismatch, expected {}, got {}",
                String::from_utf8_lossy(a),
                String::from_utf8_lossy(b)
            ),
            Error::ParseSignature(sig, hd, path) => write!(
                f,
                "failed to parse and verify signature; sigbytes: {sig:?}, hdhash: {hd:?}, pubkey_path: {path}"
            ),
            Error::RenameFile(err) => write!(f, "failed to rename file: {err:?}"),
            Error::CreateDirAll(err) => write!(f, "failed to create dir all: {err:?}"),
            Error::BuildClient(err) => write!(f, "failed to build client: {err:?}"),
            Error::ParseUrl(url) => write!(f, "failed to parse url: {url:?}"),
            Error::GetPathSegments(url) => write!(f, "failed to get path segments: {url:?}"),
            Error::ParseXmlResponse(xml) => write!(f, "failed to parse Response from xml: {xml:?}"),
            Error::RemoveDirAll(err) => write!(f, "failed to remove dir all: {err:?}"),
        }
    }
}
