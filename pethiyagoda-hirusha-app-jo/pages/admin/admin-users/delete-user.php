<?php
session_start();
require_once("../../../database/database.php");

// CSRF Protection
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $_SESSION['error'] = "Token CSRF invalide.";
        header('Location: ../../../index.php');
        exit();
    }
}

// Check if user is logged in
if (!isset($_SESSION['login'])) {
    header('Location: ../../../index.php');
    exit();
}

// Generate CSRF token if not already done
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Check if user ID is provided in URL
if (!isset($_GET['id_utilisateur'])) {
    $_SESSION['error'] = "ID de l'utilisateur manquant.";
    header("Location: manage-users.php");
    exit();
} else {
    $id_utilisateur = filter_input(INPUT_GET, 'id_utilisateur', FILTER_VALIDATE_INT);

    // Verify if user ID is valid
    if ($id_utilisateur === false) {
        $_SESSION['error'] = "ID de l'utilisateur invalide.";
        header("Location: manage-users.php");
        exit();
    } else {
        try {
            // Prepare SQL query to delete user
            $sql = "DELETE FROM UTILISATEUR WHERE id_utilisateur = :id_utilisateur";
            // Execute SQL query with parameter
            $statement = $connexion->prepare($sql);
            $statement->bindParam(':id_utilisateur', $id_utilisateur, PDO::PARAM_INT);
            $statement->execute();

            // Success message
            $_SESSION['success'] = "L'utilisateur a été supprimé avec succès.";

            // Redirect to previous page after deletion
            header('Location: manage-users.php');
            exit();
        } catch (PDOException $e) {
            $_SESSION['error'] = "Erreur lors de la suppression de l'utilisateur : " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8');
            header('Location: manage-users.php');
            exit();
        }
    }
}

// Display PHP errors (works if the option is activated locally)
error_reporting(E_ALL);
ini_set("display_errors", 1);
?>