package org.secretary.app

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/** Scroll-safe branded backdrop used by the entry, unlock, and creation flows. */
@Composable
internal fun SecretaryScreen(content: @Composable ColumnScope.() -> Unit) {
    val colors = MaterialTheme.colorScheme
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Brush.verticalGradient(listOf(colors.surface, colors.background))),
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp, vertical = 28.dp),
            verticalArrangement = Arrangement.spacedBy(18.dp),
            content = content,
        )
    }
}

/** Compact book-and-quill mark derived from the desktop refresh artwork. */
@Composable
internal fun SecretaryBrandMark(size: Dp = 60.dp) {
    val markColor = MaterialTheme.colorScheme.secondary
    val background = MaterialTheme.colorScheme.primaryContainer
    Surface(
        modifier = Modifier.size(size),
        shape = MaterialTheme.shapes.medium,
        color = background,
        tonalElevation = 2.dp,
    ) {
        Canvas(modifier = Modifier.padding(10.dp)) {
            val scale = this.size.minDimension / 48f
            fun p(x: Float, y: Float) = Offset(x * scale, y * scale)
            val book = Path().apply {
                moveTo(12.5f * scale, 11.5f * scale)
                lineTo(32.5f * scale, 11.5f * scale)
                quadraticTo(36.5f * scale, 11.5f * scale, 36.5f * scale, 15.5f * scale)
                lineTo(36.5f * scale, 37.5f * scale)
                lineTo(16.5f * scale, 37.5f * scale)
                quadraticTo(11.5f * scale, 37.5f * scale, 11.5f * scale, 32.5f * scale)
                lineTo(11.5f * scale, 16.5f * scale)
                quadraticTo(11.5f * scale, 11.5f * scale, 16.5f * scale, 11.5f * scale)
            }
            drawPath(book, markColor, style = Stroke(2.5f * scale, join = StrokeJoin.Round))
            drawLine(markColor, p(16.5f, 27.5f), p(36.5f, 27.5f), 2.5f * scale, StrokeCap.Round)
            val quill = Path().apply {
                moveTo(25f * scale, 27f * scale)
                quadraticTo(29f * scale, 10f * scale, 40f * scale, 7f * scale)
                quadraticTo(39f * scale, 18f * scale, 25f * scale, 27f * scale)
                close()
            }
            drawPath(quill, markColor)
            drawLine(background, p(24f, 28f), p(36f, 13f), 1.5f * scale, StrokeCap.Round)
        }
    }
}

@Composable
internal fun SecretaryBrandHeader(title: String, subtitle: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(16.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        SecretaryBrandMark()
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = "SECRETARY",
                color = MaterialTheme.colorScheme.secondary,
                style = MaterialTheme.typography.labelLarge,
            )
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = title,
                style = MaterialTheme.typography.headlineMedium,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = subtitle,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}

@Composable
internal fun SecretaryPanel(content: @Composable ColumnScope.() -> Unit) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        color = MaterialTheme.colorScheme.surface,
        tonalElevation = 1.dp,
        shadowElevation = 4.dp,
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
            content = content,
        )
    }
}
