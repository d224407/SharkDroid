package org.sharkdroid.ui

import android.content.Context
import android.content.Intent
import android.util.LruCache
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.input.nestedscroll.NestedScrollConnection
import androidx.compose.ui.input.nestedscroll.NestedScrollSource
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.unit.Velocity
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.sharkdroid.R
import org.sharkdroid.Tools

data class AppEntry(val label: String, val pkg: String)

fun loadApps(ctx: Context): List<AppEntry> {
    val pm = ctx.packageManager
    val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
    @Suppress("DEPRECATION")
    return pm.queryIntentActivities(launcher, 0)
        .map { AppEntry(it.loadLabel(pm).toString(), it.activityInfo.packageName) }
        .distinctBy { it.pkg }
        .filter { it.pkg != ctx.packageName }
        .sortedBy { it.label.lowercase() }
}

fun appLabel(ctx: Context, process: String): String = try {
    val pm = ctx.packageManager
    pm.getApplicationLabel(pm.getApplicationInfo(process.substringBefore(':'), 0)).toString()
} catch (_: Exception) { process }

private object AppIcons {
    private val cache = LruCache<String, ImageBitmap>(256)
    fun cached(pkg: String): ImageBitmap? = cache.get(pkg)
    fun load(ctx: Context, pkg: String): ImageBitmap? = try {
        ctx.packageManager.getApplicationIcon(pkg.substringBefore(':')).toBitmap(96, 96).asImageBitmap()
            .also { cache.put(pkg, it) }
    } catch (_: Exception) { null }
}

@Composable
fun AppIcon(pkg: String, sizeDp: Int = 40) {
    val ctx = LocalContext.current
    val icon by produceState(AppIcons.cached(pkg), pkg) {
        // produceState keeps its previous value when the key changes: reset it, or the old app's icon stays.
        value = AppIcons.cached(pkg) ?: withContext(Dispatchers.IO) { AppIcons.load(ctx, pkg) }
    }
    val shape = RoundedCornerShape((sizeDp / 4).dp)
    val img = icon
    if (img != null) Image(img, null, Modifier.size(sizeDp.dp).clip(shape))
    else Box(Modifier.size(sizeDp.dp).clip(shape).background(MaterialTheme.colorScheme.surfaceVariant))
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppPickerSheet(onSelect: (String) -> Unit, onDismiss: () -> Unit) {
    val ctx = LocalContext.current
    val apps by produceState(emptyList<AppEntry>()) { value = withContext(Dispatchers.IO) { loadApps(ctx) } }
    var query by remember { mutableStateOf("") }
    val q = query.trim()
    val shown = remember(apps, q) {
        if (q.isEmpty()) apps else apps.filter { it.label.contains(q, true) || it.pkg.contains(q, true) }
    }
    val typed = q.takeIf { Tools.validPackage(it) && apps.none { a -> a.pkg == it } }
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)) {
        Text(stringResource(R.string.target_app_pick_title), style = MaterialTheme.typography.titleLarge,
            modifier = Modifier.padding(horizontal = 24.dp))
        OutlinedTextField(
            value = query, onValueChange = { query = it.take(128) }, singleLine = true,
            label = { Text(stringResource(R.string.target_app_search)) },
            leadingIcon = { Icon(Icons.Filled.Search, null) },
            trailingIcon = { if (query.isNotEmpty()) IconButton(onClick = { query = "" }) { Icon(Icons.Filled.Clear, stringResource(R.string.action_clear_filter)) } },
            modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp, vertical = 12.dp),
        )
        // At the bottom of the list the leftover scroll and fling would drag the bottom sheet (the "jump"): eat them.
        val keepSheet = remember {
            object : NestedScrollConnection {
                override fun onPostScroll(consumed: Offset, available: Offset, source: NestedScrollSource) =
                    if (available.y < 0f) available else Offset.Zero
                override suspend fun onPostFling(consumed: Velocity, available: Velocity) =
                    if (available.y < 0f) available else Velocity.Zero
            }
        }
        LazyColumn(Modifier.fillMaxWidth().height(480.dp).nestedScroll(keepSheet), overscrollEffect = null) {
            typed?.let { t ->
                item(key = "typed") {
                    ListItem(
                        headlineContent = { Text(stringResource(R.string.target_app_use_typed, t)) },
                        leadingContent = { AppIcon(t) },
                        modifier = Modifier.clickable { onSelect(t) },
                    )
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f))
                }
            }
            items(shown, key = { it.pkg }) { a ->
                ListItem(
                    headlineContent = { Text(a.label) },
                    supportingContent = { Text(a.pkg) },
                    leadingContent = { AppIcon(a.pkg) },
                    modifier = Modifier.clickable { onSelect(a.pkg) },
                )
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f))
            }
        }
    }
}
