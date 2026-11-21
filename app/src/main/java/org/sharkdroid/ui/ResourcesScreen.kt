package org.sharkdroid.ui

import android.graphics.BitmapFactory
import android.net.Uri
import android.util.LruCache
import android.widget.MediaController
import android.widget.Toast
import android.widget.VideoView
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.outlined.Archive
import androidx.compose.material.icons.outlined.BrokenImage
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.GraphicEq
import androidx.compose.material.icons.outlined.InsertDriveFile
import androidx.compose.material.icons.outlined.Movie
import androidx.compose.material.icons.outlined.SaveAlt
import androidx.compose.material.icons.outlined.TextFields
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.sharkdroid.R
import org.sharkdroid.Resources
import org.sharkdroid.Tools
import java.io.File

private object Thumbs {
    private val cache = LruCache<String, ImageBitmap>(160)
    fun cached(path: String): ImageBitmap? = cache.get(path)
    fun decode(file: File, target: Int): ImageBitmap? = try {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeFile(file.path, bounds)
        var sample = 1
        while (maxOf(bounds.outWidth, bounds.outHeight) / (sample * 2) >= target) sample *= 2
        BitmapFactory.decodeFile(file.path, BitmapFactory.Options().apply { inSampleSize = sample })?.asImageBitmap()
    } catch (_: Throwable) { null }
    fun load(file: File): ImageBitmap? = decode(file, 256)?.also { cache.put(file.path, it) }
}

private fun kindIcon(k: Resources.Kind) = when (k) {
    Resources.Kind.IMAGE -> Icons.Outlined.BrokenImage
    Resources.Kind.VIDEO -> Icons.Outlined.Movie
    Resources.Kind.AUDIO -> Icons.Outlined.GraphicEq
    Resources.Kind.TEXT -> Icons.Outlined.Description
    Resources.Kind.DOCUMENT -> Icons.Outlined.Description
    Resources.Kind.FONT -> Icons.Outlined.TextFields
    Resources.Kind.ARCHIVE -> Icons.Outlined.Archive
    Resources.Kind.OTHER -> Icons.Outlined.InsertDriveFile
}

private fun sizeLabel(b: Long) = when {
    b >= 1 shl 20 -> String.format(java.util.Locale.US, "%.1f MB", b / 1048576.0)
    b >= 1024 -> String.format(java.util.Locale.US, "%.1f KB", b / 1024.0)
    else -> "$b B"
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ResourcesScreen(capture: File?, onBack: () -> Unit) {
    val ctx = LocalContext.current
    var items by remember { mutableStateOf<List<Resources.Item>?>(null) }
    LaunchedEffect(capture) {
        items = if (capture == null || !Tools.isCaptureFile(ctx, capture)) emptyList()
        else withContext(Dispatchers.IO) { Resources.extract(ctx, capture) }
    }
    var filter by rememberSaveable { mutableStateOf<String?>(null) }
    var open by remember { mutableStateOf<Resources.Item?>(null) }
    val list = items
    Scaffold(topBar = {
        BackTopBar(stringResource(R.string.resources_title), onBack,
            subtitle = list?.let { stringResource(R.string.resources_count, it.size) })
    }) { pad ->
        Column(Modifier.padding(pad).fillMaxSize()) {
            when {
                list == null -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
                list.isEmpty() -> Box(Modifier.fillMaxSize().padding(32.dp), contentAlignment = Alignment.Center) {
                    Text(stringResource(R.string.resources_empty), style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                else -> {
                    val kinds = Resources.Kind.values().filter { k -> list.any { it.kind == k } }
                    LazyRow(contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        item {
                            FilterChip(selected = filter == null, onClick = { filter = null },
                                label = { Text(stringResource(R.string.resources_all, list.size)) })
                        }
                        items(kinds) { k ->
                            FilterChip(selected = filter == k.name, onClick = { filter = k.name },
                                label = { Text(stringResource(kindLabel(k), list.count { it.kind == k })) })
                        }
                    }
                    val shown = remember(list, filter) { if (filter == null) list else list.filter { it.kind.name == filter } }
                    LazyVerticalGrid(GridCells.Adaptive(110.dp), modifier = Modifier.navigationBarsPadding(),
                        contentPadding = PaddingValues(8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        items(shown, key = { it.file.path }) { ResourceCell(it) { open = it } }
                    }
                }
            }
        }
    }
    open?.let { ResourceViewer(it) { open = null } }
}

private fun kindLabel(k: Resources.Kind) = when (k) {
    Resources.Kind.IMAGE -> R.string.resources_images
    Resources.Kind.VIDEO -> R.string.resources_video
    Resources.Kind.AUDIO -> R.string.resources_audio
    Resources.Kind.TEXT -> R.string.resources_text
    Resources.Kind.DOCUMENT -> R.string.resources_documents
    Resources.Kind.FONT -> R.string.resources_fonts
    Resources.Kind.ARCHIVE -> R.string.resources_archives
    Resources.Kind.OTHER -> R.string.resources_other
}

@Composable
private fun ResourceCell(item: Resources.Item, onClick: () -> Unit) {
    Surface(shape = RoundedCornerShape(12.dp), color = MaterialTheme.colorScheme.surfaceContainerHigh, onClick = onClick) {
        Column {
            Box(Modifier.fillMaxWidth().aspectRatio(1f), contentAlignment = Alignment.Center) {
                if (item.kind == Resources.Kind.IMAGE) {
                    val bmp by produceState(Thumbs.cached(item.file.path), item.file) {
                        if (value == null) value = withContext(Dispatchers.IO) { Thumbs.load(item.file) }
                    }
                    val b = bmp
                    if (b != null) Image(b, null, Modifier.fillMaxSize(), contentScale = ContentScale.Crop)
                    else Icon(Icons.Outlined.BrokenImage, null, Modifier.size(32.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
                } else {
                    Icon(kindIcon(item.kind), null, Modifier.size(36.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            Text(item.name, style = MaterialTheme.typography.labelSmall, maxLines = 2, overflow = TextOverflow.Ellipsis,
                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp))
            Text(sizeLabel(item.size) + " · " + item.mime.substringAfter('/'), style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis,
                modifier = Modifier.padding(start = 6.dp, end = 6.dp, bottom = 6.dp))
        }
    }
}

@Composable
private fun ResourceViewer(item: Resources.Item, onDismiss: () -> Unit) {
    val ctx = LocalContext.current
    val save = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        if (uri != null) {
            val ok = try {
                ctx.contentResolver.openOutputStream(uri)?.use { out -> item.file.inputStream().use { it.copyTo(out) } }; true
            } catch (_: Exception) { false }
            Toast.makeText(ctx, if (ok) R.string.resources_saved else R.string.resources_save_failed, Toast.LENGTH_SHORT).show()
        }
    }
    val preview by produceState<String?>(null, item) {
        value = if (item.kind == Resources.Kind.IMAGE || item.kind == Resources.Kind.VIDEO || item.kind == Resources.Kind.AUDIO) null
        else withContext(Dispatchers.IO) {
            val buf = ByteArray(65536)
            val n = item.file.inputStream().use { it.read(buf) }.coerceAtLeast(0)
            val b = buf.copyOf(n)
            if (item.kind == Resources.Kind.TEXT) String(b, Charsets.UTF_8) else hexDump(b.copyOf(minOf(n, 2048)))
        }
    }
    Dialog(onDismissRequest = onDismiss, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.surface) {
            Column(Modifier.navigationBarsPadding()) {
                Row(Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                    IconButton(onClick = onDismiss) { Icon(Icons.Filled.Close, stringResource(R.string.action_back)) }
                    Column(Modifier.weight(1f)) {
                        Text(item.name, style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(sizeLabel(item.size) + " · " + item.mime, style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        if (item.url.isNotEmpty()) Text(item.url, style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2, overflow = TextOverflow.Ellipsis)
                    }
                    preview?.let { p ->
                        IconButton(onClick = {
                            val cm = ctx.getSystemService(android.content.ClipboardManager::class.java)
                            cm?.setPrimaryClip(android.content.ClipData.newPlainText("resource", p))
                        }) { Icon(Icons.Filled.ContentCopy, stringResource(R.string.action_copy)) }
                    }
                    IconButton(onClick = { save.launch(item.name.substringAfterLast('/').take(100).ifBlank { "resource" }) }) {
                        Icon(Icons.Outlined.SaveAlt, stringResource(R.string.action_export))
                    }
                }
                when (item.kind) {
                    Resources.Kind.IMAGE -> ZoomImage(item.file)
                    Resources.Kind.VIDEO, Resources.Kind.AUDIO -> AndroidView(
                        modifier = Modifier.fillMaxSize(),
                        factory = { c ->
                            VideoView(c).apply {
                                val mc = MediaController(c)
                                mc.setAnchorView(this)
                                setMediaController(mc)
                                setVideoURI(Uri.fromFile(item.file))
                                setOnPreparedListener { it.isLooping = false; start() }
                            }
                        })
                    else -> Text(preview ?: "", style = Mono.small,
                        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState())
                            .horizontalScroll(rememberScrollState()).padding(12.dp))
                }
            }
        }
    }
}

@Composable
private fun ZoomImage(file: File) {
    val bmp by produceState<ImageBitmap?>(null, file) { value = withContext(Dispatchers.IO) { Thumbs.decode(file, 2048) } }
    var scale by remember { mutableStateOf(1f) }
    var offset by remember { mutableStateOf(Offset.Zero) }
    Box(Modifier.fillMaxSize().pointerInput(Unit) {
        detectTransformGestures { _, pan, zoom, _ ->
            scale = (scale * zoom).coerceIn(1f, 8f)
            offset = if (scale == 1f) Offset.Zero else offset + pan
        }
    }, contentAlignment = Alignment.Center) {
        val b = bmp
        if (b != null) Image(b, null, Modifier.fillMaxSize().graphicsLayer {
            scaleX = scale; scaleY = scale; translationX = offset.x; translationY = offset.y
        }, contentScale = ContentScale.Fit)
        else CircularProgressIndicator()
    }
}
