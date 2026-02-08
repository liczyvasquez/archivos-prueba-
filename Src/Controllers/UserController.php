<?php

namespace App\Controllers;

use App\Config\ResponseHTTP;
use App\Config\Security;
use App\Models\UserModel;
//NUEVAS IMPORTACIONES PARA PHPMAILER
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
use PHPMailer\PHPMailer\SMTP;

class UserController
{

    private $method;
    private $route;
    private $params;
    private $data;
    private $headers;

    private static $validar_rol = '/^[1-4]{1}$/';
    private static $validar_numero = '/^[0-9]+$/';
    private static $validar_texto = '/^[a-zA-Z\s]+$/';

    public function __construct($method, $route, $params, $data, $headers)
    {
        $this->method = $method;
        $this->route = $route;
        $this->params = $params;
        $this->data = $data;
        $this->headers = $headers;
    }

    final public function insertarUsuario($endpoint)
    {
        if ($this->method == 'post' && $endpoint == $this->route) {
            if (
                empty($this->data['idRol']) || empty($this->data['nombre']) ||
                empty($this->data['correo']) || empty($this->data['password']) || empty($this->data['pin']) || empty($this->data['telefono'])
            ) {
                responseHTTP::status400('Todos los campos son requeridos, proceda a llenarlos.');
                echo json_encode(ResponseHttp::$mensaje);
            } else if (!preg_match(self::$validar_rol, $this->data['idRol'])) {
                responseHTTP::status400('El rol es inválido');
                echo json_encode(ResponseHttp::$mensaje);
            }
            else if (!preg_match(self::$validar_texto, $this->data['nombre'])) {
                responseHTTP::status400('En el campo nombre debe ingresar solo texto.');
                echo json_encode(ResponseHttp::$mensaje);
            }
            else if (!filter_var($this->data['correo'], FILTER_VALIDATE_EMAIL)) {
                responseHTTP::status400('El correo debe tener el formato correcto.');
                echo json_encode(ResponseHttp::$mensaje);
            }else if (!preg_match(self::$validar_numero, $this->data['pin'])) {
                responseHTTP::status400('En el campo pin debe ingresar solo números.');
                echo json_encode(ResponseHttp::$mensaje);
            }
            else if (!preg_match(self::$validar_numero, $this->data['telefono'])) {
                responseHTTP::status400('En el campo telefono debe ingresar solo números.');
                echo json_encode(ResponseHttp::$mensaje);
            } else {
                new UserModel($this->data);
                echo json_encode(UserModel::RegistrarUsuario());
            }
        }
    }

    final public function getLogin($endpoint)
    {
        if ($this->method == 'get' && $endpoint == $this->route) {
            $correo = strtolower($this->params[1]);
            $password = $this->params[2];
            if (empty($correo) || empty($password)) {
                responseHTTP::status400('todos los campos son requeridos, proceda a llenarlos');
                echo json_encode(ResponseHTTP::$mensaje);
            } else if (!filter_var($correo, FILTER_VALIDATE_EMAIL)) {
                responseHTTP::status400('el correo debe de tener el formato correcto');
                echo json_encode(ResponseHTTP::$mensaje);
            } else {
                UserModel::setCorreo($correo);
                UserModel::setPassword($password);
                UserModel::Login();
            }
            exit;
        }
    }

    final public function getAll($endpoint)
    {
        if ($this->method == 'get' && $endpoint == $this->route) {
            echo json_encode(UserModel::getAll(), JSON_PRETTY_PRINT);
            exit;
        }
    }

    final public function getUser($endpoint)
    {
        if ($this->method == 'get' && $endpoint == $this->route) {
            Security::validateTokenJWT($this->headers, Security::secretKey());
            $telefono = $this->params[1];
            if (!isset($telefono)) {
                responseHTTP::status400('Debe ingresar un numero de telefono para proceder');
                echo json_encode(ResponseHTTP::$mensaje);
            } else if (!preg_match(self::$validar_numero, $telefono)) {
                responseHTTP::status400('El telefono solo debe de contener numeros');
                echo json_encode(ResponseHTTP::$mensaje);
            } else {
                UserModel::setTelefono($telefono);
                echo json_encode(UserModel::getUser(), JSON_PRETTY_PRINT);
                exit;
            }
        }
    }

    final public function patchPassword($endpoint)
    {
        if ($this->method == 'patch' && $endpoint == $this->route) {
            Security::validateTokenJWT($this->headers, Security::secretKey());

            if (count($this->params) < 3) {
                responseHTTP::status400('URL incorrecta. Formato esperado: User/telefono/nuevaPassword');
                echo json_encode(ResponseHTTP::$mensaje);
                return;
            }

            $telefono = $this->params[1];
            $nuevaPassword = $this->params[2];

            if (empty($telefono)) {
                responseHTTP::status400('Debe ingresar un número de teléfono para proceder');
                echo json_encode(ResponseHTTP::$mensaje);
                return;
            }

            if (!preg_match(self::$validar_numero, $telefono)) {
                responseHTTP::status400('El teléfono solo debe contener números');
                echo json_encode(ResponseHTTP::$mensaje);
                return;
            }

            if (empty($nuevaPassword)) {
                responseHTTP::status400('Debe proporcionar una nueva contraseña');
                echo json_encode(ResponseHTTP::$mensaje);
                return;
            }

            $passwordHash = password_hash($nuevaPassword, PASSWORD_DEFAULT);
            UserModel::setTelefono($telefono);
            $resultado = UserModel::updatePassword($telefono, $passwordHash);

            echo json_encode($resultado, JSON_PRETTY_PRINT);
            exit;
        }
    }

    final public function actualizarUsuario($endpoint)
    {
        if ($this->method == 'put' && $endpoint == $this->route) {
            Security::validateTokenJWT($this->headers, Security::secretKey());

            if (
                empty($this->data['idUsuario']) || empty($this->data['idRol']) ||
                empty($this->data['nombre']) ||
                empty($this->data['correo']) || 
                empty($this->data['pin']) || empty($this->data['telefono'])
            ) {
                ResponseHTTP::status400('Todos los campos son requeridos para actualizar.');
                echo json_encode(ResponseHTTP::$mensaje);
                exit;
            } else if (!preg_match(self::$validar_rol, $this->data['idRol'])) {
                ResponseHTTP::status400('El rol es inválido.');
                echo json_encode(ResponseHTTP::$mensaje);
                exit;
            } else if (!preg_match(self::$validar_texto, $this->data['nombre'])) {
                ResponseHTTP::status400('En el campo nombre debe ingresar solo texto.');
                echo json_encode(ResponseHTTP::$mensaje);
                exit;
            } else if (!filter_var($this->data['correo'], FILTER_VALIDATE_EMAIL)) {
                ResponseHTTP::status400('En el campo correo debe ingresar un correo válido.');
                echo json_encode(ResponseHTTP::$mensaje);
                exit;
            } else if (!preg_match(self::$validar_numero, $this->data['telefono'])) {
                ResponseHTTP::status400('En el campo teléfono debe ingresar solo numeros.');
                echo json_encode(ResponseHTTP::$mensaje);
                exit;
            } else {
                new UserModel($this->data);
                echo json_encode(UserModel::actualizarUsuario());
            }
        }
    }

    final public function eliminarUsuario($endpoint)
    {
        if ($this->method == 'delete' && $endpoint == $this->route) {
            Security::validateTokenJWT($this->headers, Security::secretKey());

            if (!isset($this->params[1])) {
                ResponseHTTP::status400('Debe enviar el id del usuario a eliminar.');
                echo json_encode(ResponseHTTP::$mensaje);
            } else if (!preg_match(self::$validar_numero, $this->params[1])) {
                ResponseHTTP::status400('El id del usuario debe ser numérico.');
                echo json_encode(ResponseHTTP::$mensaje);
            } else {
                UserModel::setIdUsuario($this->params[1]);
                echo json_encode(UserModel::eliminarUsuario());
            }
        }
    }

    //RECUPERAR CONTRASEÑA

   /*final public function forgotPassword($endpoint)
    {
        if ($this->method == 'post' && $endpoint == $this->route) {
            $correo = $this->data['correo'] ?? '';

            if (empty($correo)) {
                responseHTTP::status400('El correo es requerido para recuperar la contraseña.');
                echo json_encode(ResponseHttp::$mensaje);
            } else if (!filter_var($correo, FILTER_VALIDATE_EMAIL)) {
                responseHTTP::status400('El formato del correo es inválido.');
                echo json_encode(ResponseHttp::$mensaje);
            } else {
                // Buscamos al usuario en el modelo (Método que añadiste antes)
                $usuario = UserModel::getUserByEmail($correo);

                if ($usuario) {
                    $mail = new PHPMailer(true);
                    try {
                        // Configuración SMTP desde el .env
                        $mail->isSMTP();
                        $mail->Host       = $_ENV['IP'] == '127.0.0.1' ? 'smtp.gmail.com' : $_ENV['SMTP_HOST']; 
                        $mail->SMTPAuth   = true;
                        $mail->Username   = $_ENV['SMTP_USER'];
                        $mail->Password   = $_ENV['SMTP_PASS'];
                        $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
                        $mail->Port       = 465;

                        $mail->setFrom($_ENV['SMTP_USER'], 'SkinCost Notificaciones');
                        $mail->addAddress($correo, $usuario['nombre_usuario']);

                        $mail->isHTML(true);
                        $mail->CharSet = 'UTF-8';
                        $mail->Subject = 'Recuperación de Contraseña - SkinCost';
                        $mail->Body    = "
                            <h2>Hola, {$usuario['nombre_usuario']}</h2>
                            <p>Has solicitado recuperar tu acceso al sistema.</p>
                            <p>Tu PIN de seguridad registrado es: <strong>{$usuario['pin_usuario']}</strong></p>
                            <p>Tu número de teléfono es: <strong>{$usuario['telefono_usuario']}</strong></p>
                            <br>
                            <p><em>Si no solicitaste esto, ignora este correo.</em></p>
                        ";

                        $mail->send();
                        responseHTTP::status200('Correo enviado. Revisa tu bandeja de entrada.');
                        echo json_encode(ResponseHttp::$mensaje);
                    } catch (Exception $e) {
                        responseHTTP::status500('Error al enviar el correo: ' . $mail->ErrorInfo);
                        echo json_encode(ResponseHttp::$mensaje);
                    }
                } else {
                    responseHTTP::status400('El correo ingresado no existe en nuestros registros.');
                    echo json_encode(ResponseHttp::$mensaje);
                }
            }
            exit;
        }
    }*/
}
