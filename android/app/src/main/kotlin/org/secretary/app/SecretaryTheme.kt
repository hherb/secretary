package org.secretary.app

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

private val Navy = Color(0xFF17233F)
private val NavyRaised = Color(0xFF24365E)
private val Ink = Color(0xFF172238)
private val Ivory = Color(0xFFF2EFE7)
private val Paper = Color(0xFFFFFDF8)
private val Gold = Color(0xFFC99B45)
private val GoldLight = Color(0xFFDFB866)
private val Muted = Color(0xFF687083)
private val Border = Color(0xFFDDD8CC)
private val Danger = Color(0xFFB4232C)

private val LightColors = lightColorScheme(
    primary = Navy,
    onPrimary = Paper,
    primaryContainer = Color(0xFFE8EDF6),
    onPrimaryContainer = Navy,
    secondary = Gold,
    onSecondary = Navy,
    secondaryContainer = Color(0xFFF5EAD1),
    onSecondaryContainer = Ink,
    background = Ivory,
    onBackground = Ink,
    surface = Paper,
    onSurface = Ink,
    surfaceVariant = Color(0xFFEAE6DC),
    onSurfaceVariant = Muted,
    outline = Border,
    error = Danger,
    errorContainer = Color(0xFFFFF0F0),
)

private val DarkColors = darkColorScheme(
    primary = GoldLight,
    onPrimary = Color(0xFF10182A),
    primaryContainer = Color(0xFF273653),
    onPrimaryContainer = Color(0xFFF8F4E9),
    secondary = GoldLight,
    onSecondary = Color(0xFF10182A),
    secondaryContainer = Color(0xFF332B1E),
    onSecondaryContainer = Color(0xFFF6F2E9),
    background = Color(0xFF0B1220),
    onBackground = Color(0xFFF6F2E9),
    surface = Color(0xFF141D2F),
    onSurface = Color(0xFFF6F2E9),
    surfaceVariant = NavyRaised,
    onSurfaceVariant = Color(0xFFA8B0C0),
    outline = Color(0xFF2C3850),
    error = Color(0xFFFF858B),
    errorContainer = Color(0xFF351C24),
)

private val SecretaryTypography = Typography(
    headlineMedium = TextStyle(
        fontWeight = FontWeight.Bold,
        fontSize = 28.sp,
        lineHeight = 34.sp,
        letterSpacing = (-0.5).sp,
    ),
    titleLarge = TextStyle(
        fontWeight = FontWeight.Bold,
        fontSize = 22.sp,
        lineHeight = 28.sp,
        letterSpacing = (-0.25).sp,
    ),
    titleMedium = TextStyle(
        fontWeight = FontWeight.SemiBold,
        fontSize = 17.sp,
        lineHeight = 23.sp,
    ),
    labelLarge = TextStyle(
        fontWeight = FontWeight.SemiBold,
        fontSize = 14.sp,
        lineHeight = 20.sp,
    ),
    bodyLarge = TextStyle(fontSize = 16.sp, lineHeight = 24.sp),
    bodyMedium = TextStyle(fontSize = 14.sp, lineHeight = 21.sp),
)

private val SecretaryShapes = Shapes(
    small = androidx.compose.foundation.shape.RoundedCornerShape(8.dp),
    medium = androidx.compose.foundation.shape.RoundedCornerShape(14.dp),
    large = androidx.compose.foundation.shape.RoundedCornerShape(22.dp),
)

/** Shared native palette and type scale matching the desktop visual refresh. */
@Composable
fun SecretaryTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkColors else LightColors,
        typography = SecretaryTypography,
        shapes = SecretaryShapes,
        content = content,
    )
}
