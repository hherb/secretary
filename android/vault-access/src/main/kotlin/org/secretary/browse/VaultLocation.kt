package org.secretary.browse

/**
 * A remembered vault location: a human-readable [displayName] plus the SAF tree URI
 * string [treeUri] returned by the Android Storage Access Framework picker.
 *
 * Neither field is secret — the tree URI is a path-style `content://` token with no
 * key material, and the name is a folder label — so persisting this type (e.g. in
 * SharedPreferences) carries no secret-residue risk. No vault key or credential ever
 * flows through it. A plain `data class` (unlike secret-bearing `CreatedVault`)
 * because value equality / `toString` are useful and safe here. Kotlin mirror of iOS
 * `VaultLocation`.
 */
data class VaultLocation(val displayName: String, val treeUri: String)
