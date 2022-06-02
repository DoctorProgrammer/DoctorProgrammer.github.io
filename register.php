<?php

require_once "config.php";
require_once "session.php";

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['submit'])) {
    $fullname = trim($_POST['name']); 
    $email = trim($_POST['email']); 
    $password = trim($_POST['password']); 
    $confirm_password = trim($_POST["confirm_password"]); 
    $password_hash = password_hash($password, PASSWORD_BCRYPT);

    if($query = $db->prepare("SELECT * FROM users WHERE email = ?")) {
        $error = '';
        
        $query->bind_param('s', $email); 
        $query->execute(); // Store the result so we can check if the account exists in the database. 
        
        $query->store_result(); 
        if ($query->num_rows > 0) {
            $error .= '<p class="error">Email-Adresse ist bereits registriert!</p>'; 
        } else {
            if (strlen($password ) < 6) {
                $error .= '<p class="error">Passwort muss länger als 6 Zeichen sein.</p>';
            }
            if (empty($confirm_password)) {
                $error .= '<p class="error">Bitte bestätigen Sie das Passwort.</p>'; 
            } else { 
                if (empty($error) && ($password != $confirm_password)) {
                    $error .= '<p class="error">Passwort stimmt nicht überein.</p>';
                }
            }
            if (empty($error) ) {
                $insertQuery = $db->prepare("INSERT INTO users (name, email, password) VALUES(?, ?, ?);");
                $insertQuery->bind_param("sss", $fullname, $email, $password_hash);
                $result = $insertQuery->execute();
                if($result) {
                    $error .= '<p class ="success">Die Registrierung ist erfolgreich!</p>';
                } else {
                    $error .= '<p class="error">Etwas ist schief gelaufen!</p>';
                }
            }
        }
    }
    $query->close();
    $insertQuery->close();
    mysqli_close($db);
}
?>
<!DOCTYPE html>
<html lang="en">