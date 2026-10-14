<?php
declare(strict_types=1);
session_start();

/*
 * SMTP Sender - uso autorizado
 * Compatible con PHP 8+
 * Los datos SMTP se guardan en config.json en el servidor.
 */

$configFile = __DIR__ . '/config.json';

$defaults = [
    'host' => '',
    'port' => 587,
    'encryption' => 'tls', // tls, ssl, none
    'username' => '',
    'password' => '',
    'from_email' => '',
    'from_name' => '',
];

if (!file_exists($configFile)) {
    file_put_contents($configFile, json_encode($defaults, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
}
$config = json_decode((string)file_get_contents($configFile), true) ?: $defaults;
$config = array_merge($defaults, $config);

function esc(string $v): string {
    return htmlspecialchars($v, ENT_QUOTES, 'UTF-8');
}

function smtpCommand($fp, string $command, array $okCodes): string {
    fwrite($fp, $command . "\r\n");
    $response = '';
    while (($line = fgets($fp, 515)) !== false) {
        $response .= $line;
        if (strlen($line) < 4 || $line[3] === ' ') break;
    }
    $code = (int)substr($response, 0, 3);
    if (!in_array($code, $okCodes, true)) {
        throw new RuntimeException(trim($response));
    }
    return $response;
}

function smtpSend(array $c, string $to, string $subject, string $html): void {
    if (!$c['host'] || !$c['username'] || !$c['password'] || !$c['from_email']) {
        throw new RuntimeException('Faltan datos SMTP obligatorios.');
    }

    $port = (int)$c['port'];
    $transport = $c['encryption'] === 'ssl'
        ? 'ssl://' . $c['host'] . ':' . $port
        : 'tcp://' . $c['host'] . ':' . $port;

    $errno = 0; $errstr = '';
    $fp = @stream_socket_client($transport, $errno, $errstr, 20, STREAM_CLIENT_CONNECT);
    if (!$fp) throw new RuntimeException("No se pudo conectar al SMTP: $errstr ($errno)");

    stream_set_timeout($fp, 20);

    $readResponse = function() use ($fp): string {
        $response = '';
        while (($line = fgets($fp, 515)) !== false) {
            $response .= $line;
            if (strlen($line) < 4 || $line[3] === ' ') break;
        }
        return $response;
    };

    $greeting = $readResponse();
    if ((int)substr($greeting, 0, 3) !== 220) {
        fclose($fp);
        throw new RuntimeException('Respuesta SMTP inicial inválida: ' . trim($greeting));
    }

    $hostname = $_SERVER['SERVER_NAME'] ?? 'localhost';
    smtpCommand($fp, 'EHLO ' . $hostname, [250]);

    if ($c['encryption'] === 'tls') {
        smtpCommand($fp, 'STARTTLS', [220]);
        if (!stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
            fclose($fp);
            throw new RuntimeException('No se pudo activar TLS.');
        }
        smtpCommand($fp, 'EHLO ' . $hostname, [250]);
    }

    smtpCommand($fp, 'AUTH LOGIN', [334]);
    smtpCommand($fp, base64_encode($c['username']), [334]);
    smtpCommand($fp, base64_encode($c['password']), [235]);

    smtpCommand($fp, 'MAIL FROM:<' . $c['from_email'] . '>', [250]);
    smtpCommand($fp, 'RCPT TO:<' . $to . '>', [250, 251]);
    smtpCommand($fp, 'DATA', [354]);

    $encodedSubject = '=?UTF-8?B?' . base64_encode($subject) . '?=';
    $fromName = $c['from_name'] ?: $c['from_email'];

    $headers = [
        'From: ' . mb_encode_mimeheader($fromName, 'UTF-8') . ' <' . $c['from_email'] . '>',
        'To: <' . $to . '>',
        'Subject: ' . $encodedSubject,
        'Date: ' . date(DATE_RFC2822),
        'MIME-Version: 1.0',
        'Content-Type: text/html; charset=UTF-8',
        'Content-Transfer-Encoding: 8bit',
    ];

    $body = implode("\r\n", $headers) . "\r\n\r\n" . $html;
    $body = preg_replace('/^\./m', '..', $body);
    fwrite($fp, $body . "\r\n.\r\n");

    $response = $readResponse();
    if ((int)substr($response, 0, 3) !== 250) {
        fclose($fp);
        throw new RuntimeException('SMTP rechazó el mensaje: ' . trim($response));
    }

    fwrite($fp, "QUIT\r\n");
    fclose($fp);
}

$message = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'save_smtp') {
        $newConfig = [
            'host' => trim($_POST['host'] ?? ''),
            'port' => (int)($_POST['port'] ?? 587),
            'encryption' => $_POST['encryption'] ?? 'tls',
            'username' => trim($_POST['username'] ?? ''),
            'password' => $_POST['password'] ?? '',
            'from_email' => trim($_POST['from_email'] ?? ''),
            'from_name' => trim($_POST['from_name'] ?? ''),
        ];

        if (!in_array($newConfig['encryption'], ['tls', 'ssl', 'none'], true)) {
            $newConfig['encryption'] = 'tls';
        }

        file_put_contents($configFile, json_encode($newConfig, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
        $config = $newConfig;
        $message = 'Configuración SMTP guardada correctamente.';
    }

    if ($action === 'send') {
        try {
            $to = trim($_POST['to'] ?? '');
            $subject = trim($_POST['subject'] ?? '');
            $html = $_POST['html'] ?? '';

            if (!filter_var($to, FILTER_VALIDATE_EMAIL)) {
                throw new RuntimeException('Ingresá un destinatario válido.');
            }
            if ($subject === '') throw new RuntimeException('Ingresá un asunto.');
            if (trim(strip_tags($html)) === '') throw new RuntimeException('Ingresá contenido para el correo.');

            smtpSend($config, $to, $subject, $html);
            $message = 'Correo enviado correctamente.';
        } catch (Throwable $e) {
            $error = $e->getMessage();
        }
    }
}
?>
<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SMTP Sender</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#f4f7fb;color:#172033;font-family:Arial,sans-serif}
.wrap{max-width:1100px;margin:40px auto;padding:20px}.top{margin-bottom:24px}.top h1{margin:0 0 7px;font-size:30px}.top p{margin:0;color:#667085}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}.card{background:#fff;border:1px solid #e4e8ef;border-radius:16px;padding:24px;box-shadow:0 8px 30px rgba(20,30,50,.06)}
h2{font-size:19px;margin:0 0 18px}label{display:block;font-size:13px;font-weight:700;margin:13px 0 7px}
input,select,textarea{width:100%;border:1px solid #d5dbe5;border-radius:9px;padding:11px 12px;font-size:14px;background:#fff}
textarea{min-height:300px;resize:vertical;font-family:Consolas,monospace;font-size:13px}
.row{display:grid;grid-template-columns:1fr 1fr;gap:12px}.btn{margin-top:18px;border:0;border-radius:9px;padding:12px 18px;background:#155eef;color:#fff;font-weight:700;cursor:pointer}.btn:hover{opacity:.92}
.alert{padding:13px 15px;border-radius:10px;margin-bottom:18px;background:#e8f7ee;color:#137333}.error{background:#fff0f0;color:#b42318}
.small{font-size:12px;color:#667085;margin-top:9px;line-height:1.5}
@media(max-width:760px){.grid{grid-template-columns:1fr}.row{grid-template-columns:1fr}.wrap{margin:15px auto;padding:12px}}
</style>
</head>
<body>
<div class="wrap">
  <div class="top">
    <h1>SMTP Sender</h1>
    <p>Panel simple para configurar tu SMTP y enviar correos HTML.</p>
  </div>

  <?php if ($message): ?><div class="alert"><?=esc($message)?></div><?php endif; ?>
  <?php if ($error): ?><div class="alert error"><?=esc($error)?></div><?php endif; ?>

  <div class="grid">
    <section class="card">
      <h2>⚙ Configuración SMTP</h2>
      <form method="post">
        <input type="hidden" name="action" value="save_smtp">
        <label>Servidor SMTP</label>
        <input name="host" placeholder="smtp.ejemplo.com" value="<?=esc($config['host'])?>" required>

        <div class="row">
          <div>
            <label>Puerto</label>
            <input type="number" name="port" value="<?=esc((string)$config['port'])?>" required>
          </div>
          <div>
            <label>Cifrado</label>
            <select name="encryption">
              <option value="tls" <?=$config['encryption']==='tls'?'selected':''?>>TLS / STARTTLS</option>
              <option value="ssl" <?=$config['encryption']==='ssl'?'selected':''?>>SSL</option>
              <option value="none" <?=$config['encryption']==='none'?'selected':''?>>Sin cifrado</option>
            </select>
          </div>
        </div>

        <label>Usuario SMTP</label>
        <input name="username" value="<?=esc($config['username'])?>" placeholder="correo@dominio.com" required>

        <label>Contraseña SMTP</label>
        <input type="password" name="password" value="<?=esc($config['password'])?>" autocomplete="new-password" required>

        <label>Email remitente</label>
        <input type="email" name="from_email" value="<?=esc($config['from_email'])?>" placeholder="correo@dominio.com" required>

        <label>Nombre del remitente</label>
        <input name="from_name" value="<?=esc($config['from_name'])?>" placeholder="Mi empresa">

        <button class="btn" type="submit">Guardar SMTP</button>
        <div class="small">La configuración queda almacenada en <b>config.json</b>. Protegé el acceso al panel y no compartas ese archivo.</div>
      </form>
    </section>

    <section class="card">
      <h2>✉ Nuevo correo</h2>
      <form method="post">
        <input type="hidden" name="action" value="send">

        <label>Destinatario</label>
        <input type="email" name="to" placeholder="destinatario@ejemplo.com" required>

        <label>Asunto</label>
        <input name="subject" placeholder="Asunto del correo" required>

        <label>HTML del correo</label>
        <textarea name="html" placeholder="<h1>Hola</h1><p>Contenido...</p>" required></textarea>

        <button class="btn" type="submit">Enviar correo</button>
        <div class="small">Usalo para mensajes a destinatarios que hayan solicitado o autorizado recibirlos. No incluye funciones de envío masivo.</div>
      </form>
    </section>
  </div>
</div>
</body>
</html>
