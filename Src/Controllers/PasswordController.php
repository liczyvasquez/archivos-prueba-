<?php

namespace App\Controllers;

use App\Config\ResponseHTTP;
use App\Models\PasswordModel;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

class PasswordController
{
    private $method;
    private $route;
    private $data;

    public function __construct($method, $route, $data)
    {
        $this->method = $method;
        $this->route  = $route;
        $this->data   = $data;
    }

    // ===============================
    // SOLICITAR RECUPERACIÓN
    // ===============================
    final public function forgotPassword()
    {
        if ($this->method !== 'post') {
            ResponseHTTP::status400('Método no permitido');
            echo json_encode(ResponseHTTP::$mensaje);
            exit;
        }

        $correo = $this->data['correo'] ?? '';

        if (empty($correo) || !filter_var($correo, FILTER_VALIDATE_EMAIL)) {
            ResponseHTTP::status400('Correo inválido');
            echo json_encode(ResponseHTTP::$mensaje);
            exit;
        }

        $usuario = PasswordModel::getUserByEmail($correo);

        // Mensaje genérico por seguridad
        if (!$usuario) {
            ResponseHTTP::status200(
                'Si el correo existe, recibirás un enlace de recuperación'
            );
            echo json_encode(ResponseHTTP::$mensaje);
            exit;
        }

        $token = bin2hex(random_bytes(32));
        $expiresAt = date('Y-m-d H:i:s', strtotime('+1 hour'));

        PasswordModel::createResetToken(
            $usuario['id_usuario'],
            $token,
            $expiresAt
        );

        // 🔗 LINK CORRECTO (pasa por index.php)
        $link = $_ENV['URL_FRONTEND'] .
            "index.php?view=reset-password&token=" . $token;

        try {
            $mail = new PHPMailer(true);

            $mail->isSMTP();
            $mail->Host       = $_ENV['SMTP_HOST'];
            $mail->SMTPAuth   = true;
            $mail->Username   = $_ENV['SMTP_USER'];
            $mail->Password   = $_ENV['SMTP_PASS'];
            $mail->SMTPSecure = $_ENV['SMTP_ENCRYPTION'];
            $mail->Port       = $_ENV['SMTP_PORT'];
            $mail->CharSet    = 'UTF-8';

            $mail->setFrom($_ENV['SMTP_USER'], 'Sistema de Costos');
            $mail->addAddress($correo);

            $mail->isHTML(true);
            $mail->Subject = 'Recuperación de contraseña';

            $mail->Body = "
                <h2>Recuperación de contraseña</h2>
                <p>Hola <strong>{$usuario['nombre_usuario']}</strong>,</p>
                <p>Haz clic para cambiar tu contraseña:</p>
                <p>
                    <a href='{$link}'
                       style='padding:12px 20px;
                              background:#206950;
                              color:#fff;
                              text-decoration:none;
                              border-radius:5px;
                              font-weight:bold;'>
                       Cambiar contraseña
                    </a>
                </p>
                <p>Este enlace expira en 1 hora.</p>
            ";

            $mail->send();

            ResponseHTTP::status200(
                'Si el correo existe, recibirás un enlace de recuperación'
            );
            echo json_encode(ResponseHTTP::$mensaje);
            exit;

        } catch (Exception $e) {
            error_log('MAIL ERROR: ' . $mail->ErrorInfo);
            ResponseHTTP::status500('Error al enviar el correo');
            echo json_encode(ResponseHTTP::$mensaje);
            exit;
        }
    }

    // ===============================
    // RESET DE CONTRASEÑA
    // ===============================
    final public function resetPassword()
    {
        if ($this->method !== 'post') {
            ResponseHTTP::status400('Método no permitido');
            echo json_encode(ResponseHTTP::$mensaje);
            exit;
        }

        $token    = $this->data['token'] ?? '';
        $password = $this->data['password'] ?? '';

        if (empty($token) || strlen($password) < 8) {
            ResponseHTTP::status400('Datos inválidos');
            echo json_encode(ResponseHTTP::$mensaje);
            exit;
        }

        $tokenData = PasswordModel::getTokenData($token);

        if (!$tokenData) {
            ResponseHTTP::status400('Token inválido o expirado');
            echo json_encode(ResponseHTTP::$mensaje);
            exit;
        }

        $hash = password_hash($password, PASSWORD_DEFAULT);

        PasswordModel::updateUserPassword(
            $tokenData['id_usuario'],
            $hash
        );

        PasswordModel::markTokenUsed($tokenData['id']);

        ResponseHTTP::status200('Contraseña actualizada correctamente');
        echo json_encode(ResponseHTTP::$mensaje);
        exit;
    }
}