//! Helpers shared across command modules.

use crate::errors::AppError;

/// Parse a 32-char hex string into a 16-byte UUID. Bad hex folds to
/// `Internal` — the frontend only ever passes hex it received from a DTO.
pub(crate) fn parse_uuid_16(hex_str: &str) -> Result<[u8; 16], AppError> {
    let bytes = hex::decode(hex_str).map_err(|e| AppError::Internal {
        detail: format!("invalid uuid hex {hex_str:?}: {e}"),
    })?;
    bytes.try_into().map_err(|_| AppError::Internal {
        detail: format!("uuid hex {hex_str:?} is not 16 bytes"),
    })
}
