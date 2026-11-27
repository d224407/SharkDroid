package org.sharkdroid.ui

import androidx.annotation.StringRes
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AllInclusive
import androidx.compose.material.icons.filled.Bluetooth
import androidx.compose.material.icons.filled.Cable
import androidx.compose.material.icons.filled.Hub
import androidx.compose.material.icons.filled.Lan
import androidx.compose.material.icons.filled.Loop
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.SettingsEthernet
import androidx.compose.material.icons.filled.SignalCellularAlt
import androidx.compose.material.icons.filled.Usb
import androidx.compose.material.icons.filled.VpnLock
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material.icons.filled.WifiTethering
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialShapes
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.toShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import org.sharkdroid.IfaceType
import org.sharkdroid.PacketRow
import org.sharkdroid.R
import java.util.Locale

fun IfaceType.icon(): ImageVector = when (this) {
    IfaceType.ANY -> Icons.Filled.AllInclusive
    IfaceType.WIFI -> Icons.Filled.Wifi
    IfaceType.WIFI_DIRECT -> Icons.Filled.WifiTethering
    IfaceType.CELLULAR -> Icons.Filled.SignalCellularAlt
    IfaceType.VPN -> Icons.Filled.VpnLock
    IfaceType.LOOPBACK -> Icons.Filled.Loop
    IfaceType.USB -> Icons.Filled.Usb
    IfaceType.BLUETOOTH -> Icons.Filled.Bluetooth
    IfaceType.ETHERNET -> Icons.Filled.SettingsEthernet
    IfaceType.VIRTUAL -> Icons.Filled.Hub
    IfaceType.MONITOR -> Icons.Filled.Radar
    IfaceType.OTHER -> Icons.Filled.Lan
}

@StringRes
fun IfaceType.label(): Int = when (this) {
    IfaceType.ANY -> R.string.iftype_any
    IfaceType.WIFI -> R.string.iftype_wifi
    IfaceType.WIFI_DIRECT -> R.string.iftype_wifi_direct
    IfaceType.CELLULAR -> R.string.iftype_cellular
    IfaceType.VPN -> R.string.iftype_vpn
    IfaceType.LOOPBACK -> R.string.iftype_loopback
    IfaceType.USB -> R.string.iftype_usb
    IfaceType.BLUETOOTH -> R.string.iftype_bluetooth
    IfaceType.ETHERNET -> R.string.iftype_ethernet
    IfaceType.VIRTUAL -> R.string.iftype_virtual
    IfaceType.MONITOR -> R.string.iftype_monitor
    IfaceType.OTHER -> R.string.iftype_other
}

/** Wireshark-inspired colouring rules, toned down for a phone screen. */
object ProtoColors {
    private data class Pair2(val light: Color, val dark: Color)
    private val ERROR = Pair2(Color(0xFFD32F2F), Color(0xFFFF7A7A))
    private val TCPBAD = Pair2(Color(0xFFE65100), Color(0xFFFFA05C))
    private val ARP = Pair2(Color(0xFFC79100), Color(0xFFFFD54F))
    private val ICMP = Pair2(Color(0xFFC2185B), Color(0xFFF48FB1))
    private val DNS = Pair2(Color(0xFF1565C0), Color(0xFF82B1FF))
    private val HTTP = Pair2(Color(0xFF2E7D32), Color(0xFF81C784))
    private val TLS = Pair2(Color(0xFF6A1B9A), Color(0xFFCE93D8))
    private val TCP = Pair2(Color(0xFF5E35B1), Color(0xFFB39DDB))
    private val UDP = Pair2(Color(0xFF00838F), Color(0xFF80DEEA))
    private val OTHER = Pair2(Color(0xFF616161), Color(0xFFBDBDBD))

    fun colorFor(r: PacketRow, dark: Boolean): Color {
        val p = r.protocols
        val c = when {
            r.severity >= 0x800000 -> ERROR
            r.tcpBad -> TCPBAD
            p.contains(":arp") || p.startsWith("arp") -> ARP
            p.contains("icmp") -> ICMP
            p.contains(":dns") || p.contains(":mdns") -> DNS
            p.contains(":http") && !p.contains(":http2") -> HTTP
            p.contains(":tls") || p.contains(":quic") || p.contains(":http2") -> TLS
            p.contains(":tcp") -> TCP
            p.contains(":udp") -> UDP
            else -> OTHER
        }
        return if (dark) c.dark else c.light
    }
}

fun formatDuration(ms: Long): String {
    val s = (ms / 1000).coerceAtLeast(0)
    return if (s >= 3600) String.format(Locale.US, "%d:%02d:%02d", s / 3600, (s / 60) % 60, s % 60)
    else String.format(Locale.US, "%02d:%02d", s / 60, s % 60)
}

fun formatCount(n: Long): String = String.format(Locale.US, "%,d", n)

/** Corner shape for item [index] of a [count]-item group: big outer corners, small inner ones. */
fun groupedShape(index: Int, count: Int): Shape {
    val outer = 24.dp
    val inner = 6.dp
    return RoundedCornerShape(
        topStart = if (index == 0) outer else inner, topEnd = if (index == 0) outer else inner,
        bottomStart = if (index == count - 1) outer else inner, bottomEnd = if (index == count - 1) outer else inner,
    )
}

/** Decorative expressive shapes (cookie / burst polygons) used for icon containers. */
@OptIn(ExperimentalMaterial3ExpressiveApi::class)
object SharkShapesDeco {
    val hero: Shape @Composable get() = remember { MaterialShapes.SoftBurst.toShape() }
    val active: Shape @Composable get() = remember { MaterialShapes.Cookie9Sided.toShape() }
    val calm: Shape @Composable get() = remember { MaterialShapes.Cookie6Sided.toShape() }
    val round: Shape @Composable get() = remember { MaterialShapes.Circle.toShape() }
    val file: Shape @Composable get() = remember { MaterialShapes.Cookie12Sided.toShape() }
}

@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
fun EmptyState(
    icon: ImageVector,
    title: String,
    body: String,
    modifier: Modifier = Modifier,
    actions: @Composable () -> Unit = {},
) {
    Box(modifier.fillMaxSize().padding(32.dp), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) {
            Surface(shape = SharkShapesDeco.hero, color = MaterialTheme.colorScheme.secondaryContainer, modifier = Modifier.size(112.dp)) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(icon, null, Modifier.size(48.dp), tint = MaterialTheme.colorScheme.onSecondaryContainer)
                }
            }
            Spacer(Modifier.height(24.dp))
            Text(title, style = MaterialTheme.typography.headlineSmallEmphasized, textAlign = TextAlign.Center)
            Spacer(Modifier.height(8.dp))
            Text(body, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center)
            Spacer(Modifier.height(24.dp))
            actions()
        }
    }
}

@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
fun SectionHeader(@StringRes text: Int, modifier: Modifier = Modifier) {
    Text(stringResource(text), style = MaterialTheme.typography.titleSmallEmphasized, color = MaterialTheme.colorScheme.primary,
        modifier = modifier.padding(start = 24.dp, end = 16.dp, top = 24.dp, bottom = 8.dp))
}
