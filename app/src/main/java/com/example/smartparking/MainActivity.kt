package com.example.smartparking

import android.annotation.SuppressLint
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.Build
import android.Manifest
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothSocket
import android.content.Context
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.delay
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.util.UUID
import kotlin.concurrent.thread
import android.util.Patterns
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.text.NumberFormat
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.security.SecureRandom
import android.util.Base64
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

private val AzulOscuro = Color(0xFF102D52)
private val AzulPrincipal = Color(0xFF1766B1)
private val AzulClaro = Color(0xFFEAF2FC)
private val Fondo = Color(0xFFF4F7FB)
private val Verde = Color(0xFF20AD48)
private val Rojo = Color(0xFFE53935)
private val GrisTexto = Color(0xFF707786)

/** Resultado de validar las credenciales introducidas en el formulario. */
private data class ResultadoValidacionLogin(
    val esValido: Boolean,
    val correoNormalizado: String = "",
    val mensajeError: String? = null
)

/** Validación local del formulario; no reemplaza la autenticación de un servidor. */
private fun validarCredenciales(correo: String, contrasena: String): ResultadoValidacionLogin {
    val correoNormalizado = correo.trim().lowercase(Locale.ROOT)

    if (correoNormalizado.isBlank() && contrasena.isBlank()) {
        return ResultadoValidacionLogin(
            esValido = false,
            mensajeError = "Completa el correo y la contraseña."
        )
    }

    if (correoNormalizado.isBlank()) {
        return ResultadoValidacionLogin(
            esValido = false,
            mensajeError = "Ingresa tu correo electrónico."
        )
    }

    if (!Patterns.EMAIL_ADDRESS.matcher(correoNormalizado).matches()) {
        return ResultadoValidacionLogin(
            esValido = false,
            mensajeError = "Ingresa un correo electrónico válido."
        )
    }

    if (contrasena.isBlank()) {
        return ResultadoValidacionLogin(
            esValido = false,
            correoNormalizado = correoNormalizado,
            mensajeError = "Ingresa tu contraseña."
        )
    }

    if (contrasena.length < 8) {
        return ResultadoValidacionLogin(
            esValido = false,
            correoNormalizado = correoNormalizado,
            mensajeError = "La contraseña debe tener al menos 8 caracteres."
        )
    }

    return ResultadoValidacionLogin(
        esValido = true,
        correoNormalizado = correoNormalizado
    )
}

/** Obtiene un nombre visible a partir de la parte del correo anterior a @. */
private fun obtenerNombreDesdeCorreo(correo: String): String {
    val identificador = correo.substringBefore('@')
        .replace(Regex("[._-]+"), " ")
        .replace(Regex("\\s+"), " ")
        .trim()

    if (identificador.isBlank()) return "Usuario"

    return identificador.split(' ')
        .filter { it.isNotBlank() }
        .joinToString(" ") { palabra ->
            palabra.lowercase(Locale.ROOT).replaceFirstChar { caracter ->
                caracter.titlecase(Locale.ROOT)
            }
        }
}

/** Cuentas locales para la demostración. No se sincronizan entre dispositivos. */
private data class CuentaLocal(val nombre: String, val correo: String, val sal: String, val hash: String)

private fun claveDerivada(clave: String, sal: ByteArray): String {
    val spec = PBEKeySpec(clave.toCharArray(), sal, 120_000, 256)
    return try {
        val bytes = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(spec).encoded
        Base64.encodeToString(bytes, Base64.NO_WRAP)
    } finally { spec.clearPassword() }
}

private fun leerCuentas(context: Context): List<CuentaLocal> = runCatching {
    val prefs = context.getSharedPreferences("smart_parking_cuentas", Context.MODE_PRIVATE)
    val datos = JSONArray(prefs.getString("cuentas", "[]") ?: "[]")
    (0 until datos.length()).map { indice ->
        val obj = datos.getJSONObject(indice)
        CuentaLocal(obj.getString("nombre"), obj.getString("correo"), obj.getString("sal"), obj.getString("hash"))
    }
}.getOrDefault(emptyList())

private fun crearCuenta(context: Context, nombre: String, correo: String, clave: String): String? {
    val nombreLimpio = nombre.trim()
    val validacion = validarCredenciales(correo, clave)
    if (nombreLimpio.length < 2) return "Escribe tu nombre (mínimo 2 caracteres)."
    if (!validacion.esValido) return validacion.mensajeError ?: "Datos inválidos."
    val cuentas = leerCuentas(context)
    if (cuentas.any { it.correo == validacion.correoNormalizado }) return "Ya existe una cuenta con este correo."
    val sal = ByteArray(16).also { SecureRandom().nextBytes(it) }
    val cuenta = CuentaLocal(nombreLimpio, validacion.correoNormalizado,
        Base64.encodeToString(sal, Base64.NO_WRAP), claveDerivada(clave, sal))
    val datos = JSONArray()
    (cuentas + cuenta).forEach { c ->
        datos.put(JSONObject().put("nombre", c.nombre).put("correo", c.correo)
            .put("sal", c.sal).put("hash", c.hash))
    }
    val guardado = context.getSharedPreferences("smart_parking_cuentas", Context.MODE_PRIVATE)
        .edit().putString("cuentas", datos.toString()).commit()
    return if (guardado) null else "No fue posible guardar la cuenta. Inténtalo otra vez."
}

private fun autenticarCuenta(context: Context, correo: String, clave: String): CuentaLocal? {
    val cuenta = leerCuentas(context).firstOrNull { it.correo == correo.trim().lowercase(Locale.ROOT) }
        ?: return null
    return runCatching {
        val sal = Base64.decode(cuenta.sal, Base64.NO_WRAP)
        val actual = Base64.decode(claveDerivada(clave, sal), Base64.NO_WRAP)
        val esperado = Base64.decode(cuenta.hash, Base64.NO_WRAP)
        java.security.MessageDigest.isEqual(actual, esperado)
    }.getOrDefault(false).let { if (it) cuenta else null }
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            MaterialTheme {
                SmartParkingApp()
            }
        }
    }
}

@SuppressLint("MissingPermission")
private fun nombreBluetooth(dispositivo: BluetoothDevice): String =
    runCatching { dispositivo.name ?: dispositivo.address }.getOrDefault("Dispositivo")

private data class SesionParking(val inicio: Long, val fin: Long, val cobro: Int) {
    val minutos: Long get() = ((fin - inicio).coerceAtLeast(0) + 59999) / 60000
}

private fun leerSesiones(context: Context): List<SesionParking> = runCatching {
    val texto = context.getSharedPreferences("smart_parking", Context.MODE_PRIVATE)
        .getString("historial", "[]") ?: "[]"
    val array = JSONArray(texto)
    (0 until array.length()).map { i ->
        val item = array.getJSONObject(i)
        SesionParking(item.getLong("inicio"), item.getLong("fin"), item.getInt("cobro"))
    }
}.getOrDefault(emptyList())

private fun guardarSesiones(context: Context, sesiones: List<SesionParking>) {
    val array = JSONArray()
    sesiones.forEach {
        array.put(JSONObject().put("inicio", it.inicio).put("fin", it.fin).put("cobro", it.cobro))
    }
    context.getSharedPreferences("smart_parking", Context.MODE_PRIVATE)
        .edit { putString("historial", array.toString()) }
}

private fun calcularCobro(inicio: Long, fin: Long, tarifaHora: Int): Int {
    val minutos = ((fin - inicio).coerceAtLeast(0) + 59999) / 60000
    return ((minutos * tarifaHora + 59) / 60).toInt()
}

/** Bluetooth clásico SPP. Recibe LIBRE, OCUPADO o DESCONOCIDO del sensor HC-SR04. */
private class ConexionParkingBluetooth(
    private val context: Context,
    private val onEstado: (String) -> Unit,
    private val onConexion: (String) -> Unit
) {
    private val main = Handler(Looper.getMainLooper())
    private val lock = Any()
    private var generacion = 0L
    private var socket: BluetoothSocket? = null
    // El Arduino envía lecturas confirmadas y repite su estado cada 3 segundos.
    private val uuidSPP = UUID.fromString("00001101-0000-1000-8000-00805F9B34FB")

    private fun publicarEstado(id: Long, valor: String) {
        main.post { if (vigente(id)) onEstado(valor) }
    }

    private fun publicarConexion(id: Long, valor: String) {
        main.post { if (vigente(id)) onConexion(valor) }
    }

    private fun vigente(id: Long): Boolean = synchronized(lock) { generacion == id }

    @SuppressLint("MissingPermission")
    fun conectar(dispositivo: BluetoothDevice) {
        cerrar()
        val id = synchronized(lock) { generacion }
        publicarConexion(id, "Conectando a ${nombreBluetooth(dispositivo)}...")
        thread(name = "smart-parking-bluetooth") {
            var nuevo: BluetoothSocket? = null
            try {
                // Se conecta a un dispositivo previamente emparejado.
                // No usamos cancelDiscovery(): requiere BLUETOOTH_SCAN en Android 12+.
                nuevo = dispositivo.createRfcommSocketToServiceRecord(uuidSPP)
                val asignado = synchronized(lock) {
                    if (generacion == id) { socket = nuevo; true } else false
                }
                if (!asignado) return@thread
                nuevo.connect()
                if (!vigente(id)) return@thread
                publicarConexion(id, "Conectado: ${nombreBluetooth(dispositivo)}")
                val lector = BufferedReader(InputStreamReader(nuevo.inputStream))
                while (vigente(id)) {
                    val linea = lector.readLine() ?: break
                    val dato = linea.trim().uppercase(Locale.ROOT)
                    if (dato == "LIBRE" || dato == "OCUPADO" || dato == "DESCONOCIDO") {
                        publicarEstado(id, dato)
                    }
                }
                publicarConexion(id, "Desconectado")
            } catch (e: Exception) {
                publicarConexion(id, "Sin conexión: ${e.message ?: "revisar Bluetooth"}")
            } finally {
                runCatching { nuevo?.close() }
                synchronized(lock) {
                    if (generacion == id) socket = null
                }
                publicarEstado(id, "DESCONOCIDO")
            }
        }
    }

    fun cerrar() {
        val anterior = synchronized(lock) {
            generacion++
            val abierto = socket
            socket = null
            abierto
        }
        runCatching { anterior?.close() }
    }
}

@Composable
fun SmartParkingApp() {
    val context = LocalContext.current
    var correo by remember { mutableStateOf("") }
    var contrasena by remember { mutableStateOf("") }
    var mostrarContrasena by remember { mutableStateOf(false) }
    var mensajeError by remember { mutableStateOf("") }
    var ingresoCorrecto by remember { mutableStateOf(false) }
    var modoRegistro by remember { mutableStateOf(false) }
    var nombreRegistro by remember { mutableStateOf("") }
    var confirmarClave by remember { mutableStateOf("") }
    var nombreUsuario by remember { mutableStateOf("") }
    var mensajeExito by remember { mutableStateOf("") }
    var sistemaActivo by remember { mutableStateOf(true) }
    var pantallaActual by remember { mutableStateOf("Inicio") }
    var estadoSensor by remember { mutableStateOf("DESCONOCIDO") }
    var estadoConexion by remember { mutableStateOf("Sin conexión") }
    var nombreDispositivo by remember { mutableStateOf("Sin seleccionar") }
    var dispositivoConectado by remember { mutableStateOf(false) }
    var dispositivos by remember { mutableStateOf<List<BluetoothDevice>>(emptyList()) }
    var inicioSesion by remember { mutableStateOf<Long?>(null) }
    var sesiones by remember { mutableStateOf(leerSesiones(context)) }
    val preferencias = remember { context.getSharedPreferences("smart_parking", Context.MODE_PRIVATE) }
    var tarifaHora by remember { mutableIntStateOf(preferencias.getInt("tarifa_hora", 1500)) }
    var ahora by remember { mutableLongStateOf(System.currentTimeMillis()) }
    var pendienteLibre by remember { mutableLongStateOf(0L) }
    var finalizadoManual by remember { mutableStateOf(false) }

    // El controlador no pertenece al login: se cierra al salir de la pantalla o la app.
    val controlador = remember {
        ConexionParkingBluetooth(
            context = context.applicationContext,
            onEstado = { estadoSensor = it },
            onConexion = {
                estadoConexion = it
                dispositivoConectado = it.startsWith("Conectado:")
                if (it == "Desconectado" || it.startsWith("Sin conexión:")) {
                    nombreDispositivo = "Sin seleccionar"
                }
            }
        )
    }
    DisposableEffect(Unit) { onDispose { controlador.cerrar() } }
    LaunchedEffect(Unit) { while (true) { ahora = System.currentTimeMillis(); delay(1.seconds) } }

    // Un corte de Bluetooth no equivale a LIBRE. Sólo una lectura válida puede cerrar la sesión.
    LaunchedEffect(estadoSensor, sistemaActivo, ahora) {
        if (!sistemaActivo) { pendienteLibre = 0L; return@LaunchedEffect }
        if (estadoSensor == "OCUPADO") {
            pendienteLibre = 0L
            if (!finalizadoManual && inicioSesion == null) inicioSesion = System.currentTimeMillis()
        } else if (estadoSensor == "LIBRE" && inicioSesion == null) {
            finalizadoManual = false
        } else if (estadoSensor == "LIBRE" && inicioSesion != null) {
            if (pendienteLibre == 0L) pendienteLibre = System.currentTimeMillis()
            if (System.currentTimeMillis() - pendienteLibre >= 3000L) {
                val fin = System.currentTimeMillis()
                val inicio = inicioSesion!!
                sesiones = sesiones + SesionParking(inicio, fin, calcularCobro(inicio, fin, tarifaHora))
                guardarSesiones(context, sesiones)
                inicioSesion = null
                pendienteLibre = 0L
            }
        } else if (estadoSensor == "DESCONOCIDO") pendienteLibre = 0L
    }

    // Para dispositivos emparejados basta BLUETOOTH_CONNECT en Android 12+.
    // Android 11 o anteriores usan el permiso BLUETOOTH declarado en el Manifest.
    val permisoBluetooth = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
        Manifest.permission.BLUETOOTH_CONNECT else null
    val lanzadorPermiso = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { concedido ->
        estadoConexion = if (concedido) "Permiso concedido. Pulsa Buscar emparejados."
        else "Permiso denegado. Autoriza Dispositivos cercanos en Ajustes."
    }
    val permisoOk = permisoBluetooth == null ||
            ContextCompat.checkSelfPermission(context, permisoBluetooth) == PackageManager.PERMISSION_GRANTED

    @SuppressLint("MissingPermission")
    fun buscarEmparejados() {
        if (!permisoOk) {
            permisoBluetooth?.let(lanzadorPermiso::launch)
            return
        }
        val adaptador = (context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)?.adapter
        if (adaptador == null) {
            estadoConexion = "Este celular no admite Bluetooth clásico"
        } else if (!adaptador.isEnabled) {
            estadoConexion = "Activa Bluetooth desde los ajustes del celular"
        } else {
            dispositivos = adaptador.bondedDevices?.toList().orEmpty()
            estadoConexion = if (dispositivos.isEmpty()) "Empareja primero el HC-05 en Ajustes del teléfono" else "Selecciona tu módulo emparejado"
        }
    }

    Surface(modifier = Modifier.fillMaxSize(), color = Fondo) {
        if (!ingresoCorrecto) {
            if (modoRegistro) {
                PantallaRegistro(
                    nombre = nombreRegistro, onNombreChange = { nombreRegistro = it; mensajeError = "" },
                    correo = correo, onCorreoChange = { correo = it; mensajeError = "" },
                    contrasena = contrasena, onContrasenaChange = { contrasena = it; mensajeError = "" },
                    confirmar = confirmarClave, onConfirmarChange = { confirmarClave = it; mensajeError = "" },
                    mensajeError = mensajeError,
                    onCrear = {
                        if (contrasena != confirmarClave) {
                            mensajeError = "Las contraseñas no coinciden."
                        } else {
                            val error = crearCuenta(context, nombreRegistro, correo, contrasena)
                            if (error != null) mensajeError = error
                            else {
                                modoRegistro = false
                                mensajeError = ""
                                mensajeExito = "Cuenta creada correctamente. Ahora inicia sesión."
                                contrasena = ""; confirmarClave = ""
                            }
                        }
                    },
                    onVolver = { modoRegistro = false; mensajeError = ""; contrasena = ""; confirmarClave = "" }
                )
            } else {
                PantallaLogin(
                    correo = correo, onCorreoChange = { correo = it; mensajeError = "" },
                    contrasena = contrasena, onContrasenaChange = { contrasena = it; mensajeError = "" },
                    mostrarContrasena = mostrarContrasena,
                    onMostrarContrasenaChange = { mostrarContrasena = it },
                    mensajeError = mensajeError,
                    mensajeExito = mensajeExito,
                    onCrearCuenta = {
                        modoRegistro = true; mensajeError = ""; mensajeExito = ""; contrasena = ""
                    },
                    onIngresar = {
                        val resultado = validarCredenciales(correo, contrasena)
                        if (!resultado.esValido) mensajeError = resultado.mensajeError ?: "Datos inválidos"
                        else {
                            val cuenta = autenticarCuenta(context, resultado.correoNormalizado, contrasena)
                            if (cuenta == null) mensajeError = "Correo o contraseña incorrectos. Crea una cuenta si aún no tienes."
                            else {
                                correo = cuenta.correo; nombreUsuario = cuenta.nombre
                                mensajeError = ""; mensajeExito = ""; pantallaActual = "Inicio"; ingresoCorrecto = true
                            }
                        }
                    }
                )
            }
        } else {
            PantallaPrincipal(
                correo = correo, nombreRegistrado = nombreUsuario, pantallaActual = pantallaActual,
                onCambiarPantalla = { pantallaActual = it },
                sistemaActivo = sistemaActivo,
                onCambiarSistema = { sistemaActivo = !sistemaActivo },
                estadoSensor = if (sistemaActivo) estadoSensor else "DESACTIVADO",
                estadoConexion = estadoConexion,
                nombreDispositivo = nombreDispositivo,
                dispositivoConectado = dispositivoConectado,
                sesiones = sesiones,
                inicioSesion = inicioSesion,
                ahora = ahora,
                tarifaHora = tarifaHora,
                onTarifaChange = { tarifaHora = it; preferencias.edit { putInt("tarifa_hora", it) } },
                dispositivos = dispositivos,
                onBuscar = { buscarEmparejados() },
                onConectar = { dispositivo ->
                    if (permisoOk) {
                        nombreDispositivo = nombreBluetooth(dispositivo)
                        dispositivoConectado = false
                        estadoSensor = "DESCONOCIDO"
                        controlador.conectar(dispositivo)
                    } else permisoBluetooth?.let(lanzadorPermiso::launch)
                },
                onDesconectar = {
                    controlador.cerrar()
                    dispositivoConectado = false
                    nombreDispositivo = "Sin seleccionar"
                    estadoSensor = "DESCONOCIDO"
                    estadoConexion = "Desconectado manualmente"
                },
                onFinalizar = {
                    inicioSesion?.let { inicio ->
                        val fin = System.currentTimeMillis()
                        sesiones = sesiones + SesionParking(inicio, fin, calcularCobro(inicio, fin, tarifaHora))
                        guardarSesiones(context, sesiones)
                        inicioSesion = null
                        pendienteLibre = 0L
                        finalizadoManual = true
                    }
                },
                onCerrarSesion = {
                    controlador.cerrar(); estadoSensor = "DESCONOCIDO"; estadoConexion = "Sin conexión"
                    dispositivoConectado = false; nombreDispositivo = "Sin seleccionar"
                    correo = ""; contrasena = ""; mostrarContrasena = false
                    mensajeError = ""; mensajeExito = ""; pantallaActual = "Inicio"; ingresoCorrecto = false
                }
            )
        }
    }
}


@Composable
private fun PantallaRegistro(
    nombre: String, onNombreChange: (String) -> Unit,
    correo: String, onCorreoChange: (String) -> Unit,
    contrasena: String, onContrasenaChange: (String) -> Unit,
    confirmar: String, onConfirmarChange: (String) -> Unit,
    mensajeError: String, onCrear: () -> Unit, onVolver: () -> Unit
) {
    Column(
        modifier = Modifier.fillMaxSize().imePadding().verticalScroll(rememberScrollState())
            .padding(horizontal = 28.dp, vertical = 28.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Box(Modifier.size(80.dp).background(AzulClaro, RoundedCornerShape(22.dp)),
            contentAlignment = Alignment.Center) {
            Text("P", fontSize = 46.sp, fontWeight = FontWeight.Bold, color = AzulPrincipal)
        }
        Spacer(Modifier.height(16.dp))
        Text("Crear cuenta", fontSize = 28.sp, fontWeight = FontWeight.Bold, color = AzulOscuro)
        Text("Regístrate en Smart Parking", color = GrisTexto)
        Spacer(Modifier.height(20.dp))
        OutlinedTextField(nombre, onNombreChange, modifier = Modifier.fillMaxWidth(),
            label = { Text("Nombre") }, singleLine = true,
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
            shape = RoundedCornerShape(14.dp))
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(correo, onCorreoChange, modifier = Modifier.fillMaxWidth(),
            label = { Text("Correo electrónico") }, singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email, imeAction = ImeAction.Next),
            shape = RoundedCornerShape(14.dp))
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(contrasena, onContrasenaChange, modifier = Modifier.fillMaxWidth(),
            label = { Text("Contraseña (mínimo 8 caracteres)") }, singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Next),
            shape = RoundedCornerShape(14.dp))
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(confirmar, onConfirmarChange, modifier = Modifier.fillMaxWidth(),
            label = { Text("Confirmar contraseña") }, singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Done),
            shape = RoundedCornerShape(14.dp))
        if (mensajeError.isNotBlank()) {
            Spacer(Modifier.height(12.dp))
            Text(mensajeError, color = Rojo, fontSize = 13.sp, modifier = Modifier.fillMaxWidth())
        }
        Spacer(Modifier.height(18.dp))
        Button(onClick = onCrear, modifier = Modifier.fillMaxWidth().height(54.dp),
            shape = RoundedCornerShape(14.dp),
            colors = ButtonDefaults.buttonColors(containerColor = AzulPrincipal)) {
            Text("Crear cuenta", fontWeight = FontWeight.SemiBold)
        }
        Spacer(Modifier.height(8.dp))
        TextButton(onClick = onVolver) { Text("¿Ya tienes cuenta? Iniciar sesión", color = AzulPrincipal) }
    }
}

@Composable
private fun PantallaLogin(
    correo: String,
    onCorreoChange: (String) -> Unit,
    contrasena: String,
    onContrasenaChange: (String) -> Unit,
    mostrarContrasena: Boolean,
    onMostrarContrasenaChange: (Boolean) -> Unit,
    mensajeError: String,
    mensajeExito: String,
    onCrearCuenta: () -> Unit,
    onIngresar: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            // Ajusta el espacio disponible cuando aparece el teclado en el celular.
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 28.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(Modifier.height(32.dp))

        Box(
            modifier = Modifier
                .size(104.dp)
                .background(AzulClaro, RoundedCornerShape(26.dp)),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = "P",
                color = AzulPrincipal,
                fontSize = 60.sp,
                fontWeight = FontWeight.Bold
            )
        }

        Spacer(Modifier.height(18.dp))

        Text(
            text = "Smart Parking",
            fontSize = 30.sp,
            fontWeight = FontWeight.Bold,
            color = AzulOscuro
        )

        Spacer(Modifier.height(8.dp))

        Text(
            text = "Bienvenido",
            fontSize = 20.sp,
            fontWeight = FontWeight.SemiBold,
            color = AzulPrincipal
        )

        Spacer(Modifier.height(6.dp))

        Text(
            text = "Ingresa para administrar tu estacionamiento",
            fontSize = 14.sp,
            color = GrisTexto
        )

        Spacer(Modifier.height(28.dp))

        OutlinedTextField(
            value = correo,
            onValueChange = onCorreoChange,
            modifier = Modifier.fillMaxWidth(),
            label = { Text("Correo electrónico") },
            placeholder = { Text("usuario@ejemplo.com") },
            singleLine = true,
            shape = RoundedCornerShape(14.dp),
            keyboardOptions = KeyboardOptions(
                keyboardType = KeyboardType.Email,
                imeAction = ImeAction.Next
            )
        )

        Spacer(Modifier.height(16.dp))

        OutlinedTextField(
            value = contrasena,
            onValueChange = onContrasenaChange,
            modifier = Modifier.fillMaxWidth(),
            label = { Text("Contraseña") },
            singleLine = true,
            shape = RoundedCornerShape(14.dp),
            visualTransformation = if (mostrarContrasena) {
                VisualTransformation.None
            } else {
                PasswordVisualTransformation()
            },
            keyboardOptions = KeyboardOptions(
                keyboardType = KeyboardType.Password,
                imeAction = ImeAction.Done
            ),
            trailingIcon = {
                TextButton(
                    onClick = {
                        onMostrarContrasenaChange(!mostrarContrasena)
                    }
                ) {
                    Text(
                        if (mostrarContrasena) "Ocultar" else "Ver",
                        color = AzulPrincipal
                    )
                }
            }
        )

        Spacer(Modifier.height(12.dp))

        if (mensajeError.isNotEmpty()) {
            Text(
                text = mensajeError,
                color = Rojo,
                fontSize = 13.sp,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(8.dp))
        }

        Button(
            onClick = onIngresar,
            modifier = Modifier
                .fillMaxWidth()
                .height(54.dp),
            shape = RoundedCornerShape(14.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = AzulPrincipal
            )
        ) {
            Text(
                "Ingresar",
                fontSize = 16.sp,
                fontWeight = FontWeight.SemiBold
            )
        }

        Spacer(Modifier.height(12.dp))
        TextButton(onClick = onCrearCuenta) {
            Text("¿No tienes cuenta? Crear cuenta", color = AzulPrincipal)
        }
        if (mensajeExito.isNotBlank()) {
            Text(mensajeExito, color = Verde, fontSize = 13.sp)
        }
        Spacer(Modifier.height(24.dp))

        Text(
            "Sistema de estacionamiento inteligente",
            color = GrisTexto,
            fontSize = 12.sp
        )

        Spacer(Modifier.height(32.dp))
    }
}

@Composable
private fun PantallaPrincipal(
    correo: String, nombreRegistrado: String, pantallaActual: String, onCambiarPantalla: (String) -> Unit,
    sistemaActivo: Boolean, onCambiarSistema: () -> Unit,
    estadoSensor: String, estadoConexion: String, nombreDispositivo: String,
    dispositivoConectado: Boolean,
    sesiones: List<SesionParking>, inicioSesion: Long?, ahora: Long,
    tarifaHora: Int, onTarifaChange: (Int) -> Unit,
    dispositivos: List<BluetoothDevice>, onBuscar: () -> Unit,
    onConectar: (BluetoothDevice) -> Unit, onDesconectar: () -> Unit,
    onFinalizar: () -> Unit, onCerrarSesion: () -> Unit
) {
    Column(modifier = Modifier.fillMaxSize().background(Fondo)) {
        Box(modifier = Modifier.weight(1f).fillMaxWidth()) {
            when (pantallaActual) {
                "Inicio" -> Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
                    InicioDashboard(
                        nombreUsuario = nombreRegistrado.ifBlank { obtenerNombreDesdeCorreo(correo) },
                        sistemaActivo = sistemaActivo, estadoSensor = estadoSensor,
                        estadoConexion = estadoConexion, inicioSesion = inicioSesion,
                        ahora = ahora, tarifaHora = tarifaHora,
                        onCambiarSistema = onCambiarSistema, onFinalizar = onFinalizar,
                        onAbrirResumen = { onCambiarPantalla("Resumen") },
                        onAbrirBluetooth = { onCambiarPantalla("Ajustes") }
                    )
                }
                "Historial" -> PantallaHistorial(sesiones)
                "Resumen" -> PantallaResumenDia(sesiones)
                "Ajustes" -> AjustesDashboard(
                    sistemaActivo, onCambiarSistema, onCerrarSesion,
                    estadoConexion, nombreDispositivo, dispositivoConectado, dispositivos, onBuscar,
                    onConectar, onDesconectar, tarifaHora, onTarifaChange
                )
            }
        }
        NavigationBar(containerColor = Color.White) {
            listOf("Inicio" to "⌂", "Historial" to "◷", "Resumen" to "▥", "Ajustes" to "⚙").forEach { (destino, icono) ->
                NavigationBarItem(
                    selected = pantallaActual == destino,
                    onClick = { onCambiarPantalla(destino) },
                    icon = { Text(icono, fontSize = 23.sp) },
                    label = { Text(destino, fontSize = 11.sp) },
                    colors = NavigationBarItemDefaults.colors(
                        selectedIconColor = AzulPrincipal, selectedTextColor = AzulPrincipal,
                        indicatorColor = AzulClaro, unselectedIconColor = GrisTexto,
                        unselectedTextColor = GrisTexto
                    )
                )
            }
        }
    }
}

@Composable
private fun InicioDashboard(
    nombreUsuario: String, sistemaActivo: Boolean, estadoSensor: String,
    estadoConexion: String, inicioSesion: Long?, ahora: Long, tarifaHora: Int,
    onCambiarSistema: () -> Unit, onFinalizar: () -> Unit,
    onAbrirResumen: () -> Unit, onAbrirBluetooth: () -> Unit
) {
    val estado = if (sistemaActivo) estadoSensor else "DESACTIVADO"
    val ocupado = estado == "OCUPADO"
    val libre = estado == "LIBRE"
    val transcurrido = if (inicioSesion != null) (ahora - inicioSesion).coerceAtLeast(0) else 0L
    val minutos = transcurrido / 60000
    val formato = NumberFormat.getCurrencyInstance(Locale.forLanguageTag("es-CL"))
    Column(Modifier.fillMaxWidth()) {
        Column(
            Modifier.fillMaxWidth().background(AzulOscuro, RoundedCornerShape(bottomStart = 28.dp, bottomEnd = 28.dp))
                .padding(horizontal = 24.dp, vertical = 30.dp)
        ) {
            Text("SMART PARKING", color = Color.White.copy(alpha = .75f), fontSize = 12.sp, fontWeight = FontWeight.Bold, letterSpacing = 2.sp)
            Spacer(Modifier.height(20.dp))
            Text("¡Bienvenido, $nombreUsuario!", fontSize = 30.sp, fontWeight = FontWeight.Bold, color = Color.White)
            Spacer(Modifier.height(14.dp))
            Text("Administra tu estacionamiento", color = Color.White, fontSize = 15.sp)
        }
        Column(Modifier.padding(18.dp)) {
            Text("Estado del estacionamiento", fontSize = 20.sp, fontWeight = FontWeight.Bold, color = AzulOscuro)
            Spacer(Modifier.height(14.dp))
            Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(22.dp), colors = CardDefaults.cardColors(containerColor = Color.White)) {
                Row(Modifier.fillMaxWidth().padding(vertical = 22.dp, horizontal = 8.dp), horizontalArrangement = Arrangement.SpaceEvenly) {
                    IndicadorEspacios(if (libre) 1 else 0, "Libres", Verde, "✓", Modifier.weight(1f))
                    IndicadorEspacios(if (ocupado) 1 else 0, "Ocupados", Rojo, "●", Modifier.weight(1f))
                    IndicadorEspacios(1, "Monitoreado", AzulOscuro, "P", Modifier.weight(1f))
                }
            }
            Spacer(Modifier.height(12.dp))
            Text("Estado real: $estado", color = if (ocupado) Rojo else if (libre) Verde else GrisTexto, fontWeight = FontWeight.Bold)
            if (!ocupado && !libre) Text("Sin lectura válida actual; no se supone que el espacio esté libre.", color = GrisTexto, fontSize = 12.sp)
            Spacer(Modifier.height(20.dp))
            Text("Estado del sistema", fontSize = 20.sp, fontWeight = FontWeight.Bold, color = AzulOscuro)
            Spacer(Modifier.height(12.dp))
            Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(20.dp), colors = CardDefaults.cardColors(containerColor = Color.White)) {
                Column(Modifier.padding(18.dp)) {
                    Text("Arduino Uno", fontSize = 17.sp, fontWeight = FontWeight.Bold, color = AzulOscuro)
                    Text("HC-SR04 · Bluetooth clásico", fontSize = 12.sp, color = GrisTexto)
                    Spacer(Modifier.height(12.dp))
                    HorizontalDivider(color = Fondo)
                    Spacer(Modifier.height(12.dp))
                    Text(estadoConexion, color = if (estadoConexion.startsWith("Conectado:")) Verde else GrisTexto)
                    Text(if (sistemaActivo) "Monitoreo habilitado" else "Monitoreo pausado", color = GrisTexto, fontSize = 12.sp)
                }
            }
            Spacer(Modifier.height(18.dp))
            if (inicioSesion != null) {
                Card(colors = CardDefaults.cardColors(containerColor = Color.White), modifier = Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(18.dp)) {
                        Text("Sesión en curso", fontWeight = FontWeight.Bold, color = AzulOscuro)
                        Text("Tiempo: ${minutos / 60} h ${minutos % 60} min", color = GrisTexto)
                        Text("Cobro estimado: ${formato.format(calcularCobro(inicioSesion, ahora, tarifaHora))}", color = AzulPrincipal)
                        Spacer(Modifier.height(8.dp))
                        OutlinedButton(onClick = onFinalizar) { Text("Finalizar estacionamiento manualmente") }
                    }
                }
                Spacer(Modifier.height(12.dp))
            }
            Button(onClick = onCambiarSistema, modifier = Modifier.fillMaxWidth().height(58.dp), shape = RoundedCornerShape(15.dp), colors = ButtonDefaults.buttonColors(containerColor = AzulPrincipal)) {
                Text(if (sistemaActivo) "Pausar monitoreo" else "Activar monitoreo")
            }
            Spacer(Modifier.height(10.dp))
            OutlinedButton(onClick = onAbrirBluetooth, modifier = Modifier.fillMaxWidth()) { Text("Configurar Bluetooth") }
            Spacer(Modifier.height(10.dp))
            OutlinedButton(onClick = onAbrirResumen, modifier = Modifier.fillMaxWidth()) { Text("Ver resumen del día  ›") }
            Spacer(Modifier.height(16.dp))
        }
    }
}

@Composable
private fun IndicadorEspacios(
    valor: Int,
    etiqueta: String,
    color: Color,
    simbolo: String,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier.padding(horizontal = 2.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Box(
            modifier = Modifier
                .size(42.dp)
                .background(
                    color.copy(alpha = 0.12f),
                    RoundedCornerShape(12.dp)
                ),
            contentAlignment = Alignment.Center
        ) {
            Text(
                simbolo,
                color = color,
                fontSize = 22.sp,
                fontWeight = FontWeight.Bold
            )
        }

        Spacer(Modifier.height(8.dp))

        Text(
            valor.toString(),
            fontSize = 29.sp,
            fontWeight = FontWeight.Bold,
            color = color
        )

        Text(
            etiqueta,
            fontSize = 11.sp,
            color = AzulOscuro
        )
    }
}

@Composable
private fun PantallaHistorial(sesiones: List<SesionParking>) {
    val formatoFecha = SimpleDateFormat("dd/MM/yyyy HH:mm", Locale.forLanguageTag("es-CL"))
    val moneda = NumberFormat.getCurrencyInstance(Locale.forLanguageTag("es-CL"))
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp)) {
        Text("Historial", fontSize = 28.sp, fontWeight = FontWeight.Bold, color = AzulOscuro)
        Spacer(Modifier.height(8.dp))
        Text("Sesiones registradas a partir de detecciones reales", color = GrisTexto)
        Spacer(Modifier.height(20.dp))
        if (sesiones.isEmpty()) Text("Todavía no hay sesiones finalizadas.", color = GrisTexto)
        sesiones.asReversed().forEach { sesion ->
            Card(modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp), colors = CardDefaults.cardColors(containerColor = Color.White)) {
                Column(Modifier.padding(16.dp)) {
                    Text("Estacionamiento 1", fontWeight = FontWeight.Bold, color = AzulOscuro)
                    Text("Inicio: ${formatoFecha.format(Date(sesion.inicio))}", color = GrisTexto)
                    Text("Fin: ${formatoFecha.format(Date(sesion.fin))}", color = GrisTexto)
                    Text("Duración: ${sesion.minutos} min", color = GrisTexto)
                    Text("Cobro: ${moneda.format(sesion.cobro)}", color = AzulPrincipal)
                }
            }
        }
    }
}

@SuppressLint("MissingPermission")
@Composable
private fun AjustesDashboard(
    sistemaActivo: Boolean, onCambiarSistema: () -> Unit, onCerrarSesion: () -> Unit,
    estadoConexion: String, nombreDispositivo: String, dispositivoConectado: Boolean,
    dispositivos: List<BluetoothDevice>,
    onBuscar: () -> Unit, onConectar: (BluetoothDevice) -> Unit,
    onDesconectar: () -> Unit, tarifaHora: Int, onTarifaChange: (Int) -> Unit
) {
    var textoTarifa by remember(tarifaHora) { mutableStateOf(tarifaHora.toString()) }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp)) {
        Text("Ajustes", fontSize = 28.sp, fontWeight = FontWeight.Bold, color = AzulOscuro)
        Spacer(Modifier.height(8.dp))
        Text("Configuración de Smart Parking", color = GrisTexto)
        Spacer(Modifier.height(20.dp))
        Card(colors = CardDefaults.cardColors(containerColor = Color.White)) {
            Row(Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("Monitoreo real", fontWeight = FontWeight.SemiBold, color = AzulOscuro)
                    Text(if (sistemaActivo) "Activo" else "Pausado", color = GrisTexto)
                }
                Switch(checked = sistemaActivo, onCheckedChange = { onCambiarSistema() })
            }
        }
        Spacer(Modifier.height(20.dp))
        Text("Bluetooth", fontSize = 20.sp, fontWeight = FontWeight.Bold, color = AzulOscuro)
        Text(estadoConexion, color = if (dispositivoConectado) Verde else AzulPrincipal)
        Spacer(Modifier.height(10.dp))
        if (dispositivoConectado) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = AzulClaro)
            ) {
                Column(Modifier.padding(16.dp)) {
                    Text("● Dispositivo conectado", color = Verde, fontWeight = FontWeight.Bold)
                    Spacer(Modifier.height(6.dp))
                    Text(nombreDispositivo, color = AzulOscuro, fontWeight = FontWeight.SemiBold)
                    Spacer(Modifier.height(12.dp))
                    OutlinedButton(onClick = onDesconectar, modifier = Modifier.fillMaxWidth()) {
                        Text("Desconectar dispositivo")
                    }
                }
            }
        } else {
            Button(onClick = onBuscar, modifier = Modifier.fillMaxWidth()) {
                Text("Buscar dispositivos emparejados")
            }
            dispositivos.forEach { dispositivo ->
                val nombre = nombreBluetooth(dispositivo)
                OutlinedButton(onClick = { onConectar(dispositivo) }, modifier = Modifier.fillMaxWidth()) {
                    Text("Conectar: $nombre")
                }
            }
        }
        Spacer(Modifier.height(20.dp))
        Text("Tarifa por hora (CLP)", fontWeight = FontWeight.Bold, color = AzulOscuro)
        OutlinedTextField(
            value = textoTarifa, onValueChange = { textoTarifa = it.filter(Char::isDigit).take(7) },
            label = { Text("Pesos chilenos") }, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.fillMaxWidth(), singleLine = true
        )
        OutlinedButton(onClick = { textoTarifa.toIntOrNull()?.takeIf { it > 0 }?.let(onTarifaChange) }, modifier = Modifier.fillMaxWidth()) {
            Text("Guardar tarifa")
        }
        Spacer(Modifier.height(16.dp))
        Text("Empareja el HC-05 desde Ajustes de Android antes de conectarlo aquí. El sistema utiliza Bluetooth clásico SPP.", color = GrisTexto, fontSize = 13.sp)
        Spacer(Modifier.height(24.dp))
        OutlinedButton(onClick = onCerrarSesion, modifier = Modifier.fillMaxWidth()) { Text("Cerrar sesión") }
    }
}

@Composable
private fun PantallaResumenDia(sesiones: List<SesionParking>) {
    val formatoFecha = SimpleDateFormat("EEEE d 'de' MMMM", Locale.forLanguageTag("es-CL"))
    val fecha = formatoFecha.format(Date()).replaceFirstChar { it.uppercase() }
    val calendario = java.util.Calendar.getInstance()
    fun mismoDia(t: Long): Boolean {
        val otro = java.util.Calendar.getInstance().apply { timeInMillis = t }
        return calendario.get(java.util.Calendar.YEAR) == otro.get(java.util.Calendar.YEAR) &&
                calendario.get(java.util.Calendar.DAY_OF_YEAR) == otro.get(java.util.Calendar.DAY_OF_YEAR)
    }
    val hoy = sesiones.filter { mismoDia(it.fin) }
    val totalSesiones = hoy.size
    val ingresos = hoy.sumOf { it.cobro }
    val minutosAcumulados = hoy.sumOf { it.minutos }
    val promedioMinutos = if (totalSesiones == 0) 0 else minutosAcumulados / totalSesiones
    val horas = minutosAcumulados / 60
    val minutos = minutosAcumulados % 60
    val formatoMoneda = NumberFormat.getCurrencyInstance(Locale.forLanguageTag("es-CL"))
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp)) {
        Text("Resumen del día", fontSize = 28.sp, fontWeight = FontWeight.Bold, color = AzulOscuro)
        Spacer(Modifier.height(6.dp))
        Text(fecha, fontSize = 15.sp, color = GrisTexto)
        Spacer(Modifier.height(8.dp))
        Text("Registros reales guardados en este teléfono", fontSize = 12.sp, color = AzulPrincipal)
        Spacer(Modifier.height(24.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            TarjetaResumen("Estacionamientos", totalSesiones.toString(), "Sesiones finalizadas", AzulPrincipal, Modifier.weight(1f))
            TarjetaResumen("Ingresos", formatoMoneda.format(ingresos), "Total del día", Verde, Modifier.weight(1f))
        }
        Spacer(Modifier.height(12.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            TarjetaResumen("Tiempo total", "$horas h $minutos min", "Tiempo acumulado", AzulOscuro, Modifier.weight(1f))
            TarjetaResumen("Promedio", "$promedioMinutos min", "Por estacionamiento", Color(0xFF8A5AC2), Modifier.weight(1f))
        }
        Spacer(Modifier.height(24.dp))
        Text("Detalle de la jornada", fontSize = 20.sp, fontWeight = FontWeight.Bold, color = AzulOscuro)
        Spacer(Modifier.height(12.dp))
        Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = Color.White)) {
            Column(Modifier.padding(18.dp)) {
                FilaDetalleResumen("Sesiones finalizadas", totalSesiones.toString())
                HorizontalDivider(Modifier.padding(vertical = 12.dp), color = Fondo)
                FilaDetalleResumen("Tiempo acumulado", "$horas h $minutos min")
                HorizontalDivider(Modifier.padding(vertical = 12.dp), color = Fondo)
                FilaDetalleResumen("Ingreso acumulado", formatoMoneda.format(ingresos))
                HorizontalDivider(Modifier.padding(vertical = 12.dp), color = Fondo)
                FilaDetalleResumen("Estado de los datos", "Registrados", AzulPrincipal)
            }
        }
        Spacer(Modifier.height(20.dp))
        Text("Los totales corresponden a sesiones finalizadas. El cobro es calculado según la tarifa configurada.", color = GrisTexto, fontSize = 13.sp)
    }
}

@Composable
private fun TarjetaResumen(
    titulo: String,
    valor: String,
    detalle: String,
    color: Color,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier,
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color.White
        ),
        elevation = CardDefaults.cardElevation(
            defaultElevation = 2.dp
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp)
        ) {
            Text(
                titulo,
                fontSize = 13.sp,
                color = GrisTexto
            )

            Spacer(Modifier.height(12.dp))

            Text(
                valor,
                fontSize = 21.sp,
                fontWeight = FontWeight.Bold,
                color = color
            )

            Spacer(Modifier.height(6.dp))

            Text(
                detalle,
                fontSize = 11.sp,
                color = GrisTexto
            )
        }
    }
}

@Composable
private fun FilaDetalleResumen(
    concepto: String,
    valor: String,
    colorValor: Color = AzulOscuro
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            concepto,
            modifier = Modifier.weight(1f),
            fontSize = 13.sp,
            color = GrisTexto
        )

        Spacer(Modifier.width(8.dp))

        Text(
            valor,
            fontSize = 13.sp,
            fontWeight = FontWeight.SemiBold,
            color = colorValor
        )
    }
}


