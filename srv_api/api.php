<?php
// Логика обработки запроса
$message = "";
$db_result = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input_key = $_POST['api_key'] ?? '';
    $client_id = $_POST['client_id'] ?? '';

    // 1. Читаем файл с секретом
    $secret_path = '/tmp/secret.txt';
    $server_secret = file_exists($secret_path) ? trim(file_get_contents($secret_path)) : null;

    if (!$server_secret) {
        $message = "Ошибка: Файл секрета не найден на сервере.";
    } elseif ($input_key === $server_secret) {
        $message = "Ключ подтвержден. Доступ разрешен.";

        // 2. Работа с БД (если введен ID клиента)
        if (!empty($client_id)) {
            $db_host = '172.1.1.1';
            $db_user = 'your_user';
            $db_pass = 'your_password';
            $db_name = 'your_database';

            // Используем mysqli для подключения
            $conn = @new mysqli($db_host, $db_user, $db_pass, $db_name);

            if ($conn->connect_error) {
                $db_result = "Ошибка подключения к БД (172.1.1.1): " . $conn->connect_error;
            } else {
                $stmt = $conn->prepare("SELECT name FROM clients WHERE id = ?");
                $stmt->bind_param("i", $client_id);
                $stmt->execute();
                $result = $stmt->get_result();
                
                if ($row = $result->fetch_assoc()) {
                    $db_result = "Данные найдены: " . $row['name'];
                } else {
                    $db_result = "Клиент с ID $client_id не найден.";
                }
                $stmt->close();
                $conn->close();
            }
        }
    } else {
        $message = "Ошибка: Неверный API ключ.";
    }
}
?>

<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>API PHP Terminal</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #1a1a1a; color: #dfe6e9; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .container { background: #2d3436; padding: 2rem; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); width: 400px; }
        h1 { color: #00d2d3; text-align: center; font-size: 1.5rem; }
        label { display: block; margin: 15px 0 5px; font-size: 0.8rem; color: #8395a7; }
        input { width: 100%; padding: 10px; background: #353b48; border: 1px solid #57606f; border-radius: 5px; color: white; box-sizing: border-box; }
        button { width: 100%; padding: 10px; margin-top: 20px; background: #00d2d3; border: none; border-radius: 5px; font-weight: bold; cursor: pointer; }
        .status-box { margin-top: 20px; padding: 10px; border-radius: 5px; font-size: 0.9rem; background: #3b3b3b; }
        .success { color: #55efc4; }
        .error { color: #ff7675; }
    </style>
</head>
<body>

<div class="container">
    <h1>Internal API Handler</h1>
    
    <form method="POST">
        <label>API KEY (from /tmp/secret.txt)</label>
        <input type="password" name="api_key" required>

        <label>CLIENT ID (SQL Lookup)</label>
        <input type="number" name="client_id">

        <button type="submit">Выполнить запрос</button>
    </form>

    <?php if ($message || $db_result): ?>
        <div class="status-box">
            <div class="<?= strpos($message, 'Ошибка') === false ? 'success' : 'error' ?>">
                <?= htmlspecialchars($message) ?>
            </div>
            <?php if ($db_result): ?>
                <div style="margin-top: 10px; border-top: 1px solid #444; pt: 10px;">
                    <?= htmlspecialchars($db_result) ?>
                </div>
            <?php endif; ?>
        </div>
    <?php endif; ?>
</div>

</body>
</html>
