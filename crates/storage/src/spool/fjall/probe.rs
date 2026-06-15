use std::collections::BTreeMap;

use crate::spool::{
    SpoolProbe, StorageError,
    marker::{read_spool_marker, read_spool_ready_marker},
};

use super::store::{FjallSpool, decode_sequence_key};

impl FjallSpool {
    pub fn probe(path: impl AsRef<std::path::Path>) -> Result<SpoolProbe, StorageError> {
        let path = path.as_ref();
        if !path.try_exists()? {
            return Ok(SpoolProbe::Missing);
        }
        if !read_spool_marker(path)? {
            return Ok(SpoolProbe::Incomplete {
                reason: "spool marker is missing".to_string(),
            });
        }
        if !read_spool_ready_marker(path)? {
            return Ok(SpoolProbe::Incomplete {
                reason: "spool ready marker is missing".to_string(),
            });
        }

        match Self::open(path) {
            Ok(spool) => Ok(SpoolProbe::Available {
                snapshot: spool.snapshot()?,
                export_cursors: spool.export_cursor_snapshot()?,
            }),
            Err(StorageError::Fjall(fjall::Error::Locked)) => Ok(SpoolProbe::Busy {
                reason: "spool database is locked by another process".to_string(),
            }),
            Err(error) => Err(error),
        }
    }

    pub fn is_initialized(path: impl AsRef<std::path::Path>) -> Result<bool, StorageError> {
        Ok(matches!(
            Self::probe(path)?,
            SpoolProbe::Available { .. } | SpoolProbe::Busy { .. }
        ))
    }

    fn export_cursor_snapshot(&self) -> Result<BTreeMap<String, u64>, StorageError> {
        let mut cursors = BTreeMap::new();
        for item in self.export_cursors.iter() {
            let (key, value) = item.into_inner()?;
            let sink = String::from_utf8(key.as_ref().to_vec())
                .map_err(|source| StorageError::InvalidCursorSinkName { source })?;
            if value.len() != 8 {
                return Err(StorageError::InvalidCursor {
                    sink,
                    len: value.len(),
                });
            }
            cursors.insert(sink, decode_sequence_key(value.as_ref()));
        }
        Ok(cursors)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use probe_core::SpoolPayloadSchema;
    use tempfile::tempdir;

    use crate::spool::{
        SpoolPayload, SpoolProbe, StorageError,
        marker::{SPOOL_MARKER_CONTENT, SPOOL_MARKER_FILE, SPOOL_READY_FILE},
    };

    use super::*;

    #[test]
    fn initialization_probe_does_not_create_spool() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;

        assert!(!FjallSpool::is_initialized(temp.path())?);
        assert!(temp.path().read_dir()?.next().is_none());
        Ok(())
    }

    #[test]
    fn initialization_probe_rejects_marker_without_ready_marker()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        fs::write(temp.path().join(SPOOL_MARKER_FILE), SPOOL_MARKER_CONTENT)?;

        assert!(!FjallSpool::is_initialized(temp.path())?);
        assert!(!temp.path().join(SPOOL_READY_FILE).try_exists()?);
        Ok(())
    }

    #[test]
    fn initialization_probe_rejects_invalid_spool_marker() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = tempdir()?;
        fs::write(
            temp.path().join(SPOOL_MARKER_FILE),
            b"not-an-sssa-probe-spool\n",
        )?;

        let error = FjallSpool::probe(temp.path()).expect_err("invalid marker must fail fast");

        assert!(matches!(error, StorageError::InvalidSpoolMarker { .. }));
        Ok(())
    }

    #[test]
    fn open_rejects_invalid_spool_marker_without_initializing()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        fs::write(
            temp.path().join(SPOOL_MARKER_FILE),
            b"not-an-sssa-probe-spool\n",
        )?;

        let error = match FjallSpool::open(temp.path()) {
            Ok(_) => panic!("invalid marker must fail before DB open"),
            Err(error) => error,
        };

        assert!(matches!(error, StorageError::InvalidSpoolMarker { .. }));
        assert!(!temp.path().join(SPOOL_READY_FILE).try_exists()?);
        Ok(())
    }

    #[test]
    fn open_writes_spool_markers() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;

        let _spool = FjallSpool::open(temp.path())?;

        assert!(FjallSpool::is_initialized(temp.path())?);
        Ok(())
    }

    #[test]
    fn status_probe_reports_snapshot_and_export_cursors() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        spool.append_ingress(test_payload(b"raw-one"))?;
        spool.append_export(test_payload(b"event-one"))?;
        spool.append_export(test_payload(b"event-two"))?;
        spool.ack_export("primary", 1)?;
        drop(spool);

        let probe = FjallSpool::probe(temp.path())?;

        let SpoolProbe::Available {
            snapshot,
            export_cursors,
        } = probe
        else {
            panic!("expected available spool probe");
        };
        assert_eq!(snapshot.last_ingress_sequence, 1);
        assert_eq!(snapshot.last_export_sequence, 2);
        assert_eq!(export_cursors.get("primary"), Some(&1));
        Ok(())
    }

    fn test_payload(bytes: &[u8]) -> SpoolPayload {
        SpoolPayload::new(SpoolPayloadSchema::EventEnvelopeJson, bytes)
    }
}
