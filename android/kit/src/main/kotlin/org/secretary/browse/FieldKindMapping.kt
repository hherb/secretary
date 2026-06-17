package org.secretary.browse

/** Pure map from the FFI `FieldHandle.isText()` flag to the domain [FieldKind]. */
fun fieldKindOf(isText: Boolean): FieldKind = if (isText) FieldKind.Text else FieldKind.Bytes
