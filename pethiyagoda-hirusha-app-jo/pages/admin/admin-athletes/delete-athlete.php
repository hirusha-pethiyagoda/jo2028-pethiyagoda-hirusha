<?php
session_start();

// Vérification si l'utilisateur est connecté
if (!isset($_SESSION['login'])) {
    header('Location: ../../../index.php');
    exit();
}

// Vérification du jeton CSRF
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die('Erreur de validation CSRF.');
    }
}

require_once("../../../database/database.php");

// Vérification de l'existence de l'ID de l'athlète
if (!isset($_GET['id_athlete'])) {
    $_SESSION['error'] = "ID de l'athlète non spécifié.";
    header("Location: manage-athletes.php");
    exit();
}

$id_athlete = intval($_GET['id_athlete']);

// Vérification si l'athlète existe
try {
    $query = "SELECT * FROM ATHLETE WHERE id_athlete = :id_athlete";
    $statement = $connexion->prepare($query);
    $statement->bindParam(':id_athlete', $id_athlete, PDO::PARAM_INT);
    $statement->execute();
    
    if ($statement->rowCount() === 0) {
        $_SESSION['error'] = "Athlète non trouvé.";
        header("Location: manage-athletes.php");
        exit();
    }
} catch (PDOException $e) {
    $_SESSION['error'] = "Erreur lors de la vérification de l'athlète : " . $e->getMessage();
    header("Location: manage-athletes.php");
    exit();
}

// Si le formulaire est soumis
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    try {
        // Début de la transaction
        $connexion->beginTransaction();

        // Suppression des résultats associés à l'athlète
        $query_results = "DELETE FROM PARTICIPER WHERE id_athlete = :id_athlete";
        $statement_results = $connexion->prepare($query_results);
        $statement_results->bindParam(':id_athlete', $id_athlete, PDO::PARAM_INT);
        $statement_results->execute();

        // Suppression de l'athlète
        $query_athlete = "DELETE FROM ATHLETE WHERE id_athlete = :id_athlete";
        $statement_athlete = $connexion->prepare($query_athlete);
        $statement_athlete->bindParam(':id_athlete', $id_athlete, PDO::PARAM_INT);
        $statement_athlete->execute();

        // Validation de la transaction
        $connexion->commit();

        $_SESSION['success'] = "L'athlète et ses résultats associés ont été supprimés avec succès.";
        header("Location: manage-athletes.php");
        exit();

    } catch (PDOException $e) {
        // Annulation de la transaction en cas d'erreur
        $connexion->rollBack();
        $_SESSION['error'] = "Erreur lors de la suppression : " . $e->getMessage();
        header("Location: manage-athletes.php");
        exit();
    }
}

// Génération d'un nouveau jeton CSRF
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
?>

<!DOCTYPE html>
<html lang="fr">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="../../../css/normalize.css">
    <link rel="stylesheet" href="../../../css/styles-computer.css">
    <link rel="stylesheet" href="../../../css/styles-responsive.css">
    <link rel="shortcut icon" href="../../../img/favicon.ico" type="image/x-icon">
    <title>Supprimer un Athlète - Jeux Olympiques 2024</title>
    <style>
         .confirmation-box {
            background-color: white;
            border: 1px solid #f5c6cb;
            border-radius: 5px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .delete-button {
            background-color: #dc3545;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            margin: 10px;
        }
        .cancel-button {
            background-color: #6c757d;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            margin: 10px;
            text-decoration: none;
            display: inline-block;
        }
        .delete-button:hover {
            background-color: #c82333;
        }
        .cancel-button:hover {
            background-color: #5a6268;
        }
    </style>
</head>

<body>
    <header>
        <nav>
            <ul class="menu">
                <li><a href="../admin.php">Accueil Administration</a></li>
                <li><a href="../admin-sports/manage-sports.php">Gestion Sports</a></li>
                <li><a href="../admin-places/manage-places.php">Gestion Lieux</a></li>
                <li><a href="../admin-countries/manage-countries.php">Gestion Pays</a></li>
                <li><a href="../admin-events/manage-events.php">Gestion Epreuves</a></li>
                <li><a href="../admin-athletes/manage-athletes.php">Gestion Athlètes</a></li>
                <li><a href="../admin-results/manage-results.php">Gestion Résultats</a></li>
                <li><a href="../logout.php">Déconnexion</a></li>
            </ul>
        </nav>
    </header>
    
    <main>
        <h1>Supprimer un Athlète</h1>
        
        <div class="confirmation-box">
            <p>Êtes-vous sûr de vouloir supprimer cet athlète ?</p>
            <p>Cette action est irréversible et supprimera également tous les résultats associés à cet athlète.</p>
            
            <form method="post" action="delete-athlete.php?id_athlete=<?= $id_athlete ?>">
                <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                <button type="submit" class="delete-button">Confirmer la suppression</button>
                <a href="manage-athletes.php" class="cancel-button">Annuler</a>
            </form>
        </div>
    </main>

    <footer>
        <figure>
            <img src="../../../img/logo-jo.png" alt="logo Jeux Olympiques 2024">
        </figure>
    </footer>
</body>

</html>