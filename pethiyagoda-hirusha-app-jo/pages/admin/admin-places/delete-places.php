<?php
session_start();
require_once("../../../database/database.php");

// Protection CSRF
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $_SESSION['error'] = "Token CSRF invalide.";
        header('Location: ../../../index.php');
        exit();
    }
}

// Vérifiez si l'utilisateur est connecté
if (!isset($_SESSION['login'])) {
    header('Location: ../../../index.php');
    exit();
}

// Génération du token CSRF si ce n'est pas déjà fait
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Vérifiez si l'ID du lieu est fourni dans l'URL
if (!isset($_GET['id_lieu'])) {
    $_SESSION['error'] = "ID du lieu manquant.";
    header("Location: manage-places.php");
    exit();
} else {
    $id_lieu = filter_input(INPUT_GET, 'id_lieu', FILTER_VALIDATE_INT);

    // Vérifiez si l'ID du lieu est un entier valide
    if ($id_lieu === false) {
        $_SESSION['error'] = "ID du lieu invalide.";
        header("Location: manage-places.php");
        exit();
    } else {
        try {
            // Préparez la requête SQL pour supprimer le lieu
            $sql = "DELETE FROM LIEU WHERE id_lieu = :id_lieu";
            // Exécutez la requête SQL avec le paramètre
            $statement = $connexion->prepare($sql);
            $statement->bindParam(':id_lieu', $id_lieu, PDO::PARAM_INT);
            $statement->execute();

            // Message de succès
            $_SESSION['success'] = "Le lieu a été supprimé avec succès.";

            // Redirigez vers la page précédente après la suppression
            header('Location: manage-places.php');
            exit();
        } catch (PDOException $e) {
            $_SESSION['error'] = "Erreur lors de la suppression du lieu : " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8');
            header('Location: manage-places.php');
            exit();
        }
    }
}

// Afficher les erreurs en PHP (fonctionne à condition d'avoir activé l'option en local)
error_reporting(E_ALL);
ini_set("display_errors", 1);
?>