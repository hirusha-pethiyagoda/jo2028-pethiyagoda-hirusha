<?php
session_start();

// Vérifiez si l'utilisateur est connecté
if (!isset($_SESSION['login'])) {
    header('Location: ../../../index.php');
    exit();
}

$login = $_SESSION['login'];
$nom_utilisateur = $_SESSION['prenom_utilisateur'];
$prenom_utilisateur = $_SESSION['nom_utilisateur'];

// Vérification du jeton CSRF
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die('Erreur de validation CSRF.');
    }
}

// Génération d'un nouveau jeton CSRF
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));

require_once("../../../database/database.php");

// Récupération de l'ID de l'épreuve à supprimer
$id_epreuve = isset($_GET['id_epreuve']) ? intval($_GET['id_epreuve']) : null;

if (!$id_epreuve) {
    $_SESSION['error'] = "ID de l'épreuve non spécifié.";
    header("Location: manage-events.php");
    exit();
}

// Vérification de l'existence de l'épreuve
try {
    $query = "SELECT nom_epreuve FROM EPREUVE WHERE id_epreuve = :id_epreuve";
    $statement = $connexion->prepare($query);
    $statement->bindParam(':id_epreuve', $id_epreuve, PDO::PARAM_INT);
    $statement->execute();
    $epreuve = $statement->fetch(PDO::FETCH_ASSOC);

    if (!$epreuve) {
        $_SESSION['error'] = "Épreuve non trouvée.";
        header("Location: manage-events.php");
        exit();
    }
} catch (PDOException $e) {
    $_SESSION['error'] = "Erreur lors de la récupération de l'épreuve : " . $e->getMessage();
    header("Location: manage-events.php");
    exit();
}

// Traitement de la suppression
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    try {
        // Début de la transaction
        $connexion->beginTransaction();

        // Supprimer d'abord les références dans la table PARTICIPER
        $query_participer = "DELETE FROM PARTICIPER WHERE id_epreuve = :id_epreuve";
        $statement_participer = $connexion->prepare($query_participer);
        $statement_participer->bindParam(':id_epreuve', $id_epreuve, PDO::PARAM_INT);
        $statement_participer->execute();

        // Ensuite, supprimer l'épreuve
        $query_epreuve = "DELETE FROM EPREUVE WHERE id_epreuve = :id_epreuve";
        $statement_epreuve = $connexion->prepare($query_epreuve);
        $statement_epreuve->bindParam(':id_epreuve', $id_epreuve, PDO::PARAM_INT);
        $statement_epreuve->execute();

        // Valider la transaction
        $connexion->commit();

        $_SESSION['success'] = "L'épreuve a été supprimée avec succès.";
        header("Location: manage-events.php");
        exit();
    } catch (PDOException $e) {
        // En cas d'erreur, annuler la transaction
        $connexion->rollBack();
        $_SESSION['error'] = "Erreur lors de la suppression de l'épreuve : " . $e->getMessage();
        header("Location: manage-events.php");
        exit();
    }
}
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
    <title>Supprimer une épreuve - Jeux Olympiques 2024</title>
    <style>
        .confirmation-box {
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            border-radius: 5px;
            padding: 20px;
            margin-bottom: 20px;
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
        <h1>Supprimer une épreuve</h1>
        <div class="confirmation-box">
            <p>Êtes-vous sûr de vouloir supprimer l'épreuve suivante ?</p>
            <p><strong><?= htmlspecialchars($epreuve['nom_epreuve']) ?></strong></p>
            <p>Cette action est irréversible.</p>
        </div>
        <form action="delete-events.php?id_epreuve=<?= $id_epreuve ?>" method="post">
            <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
            <input type="submit" value="Confirmer la suppression" onclick="return confirm('Êtes-vous vraiment sûr de vouloir supprimer cette épreuve ?');">
        </form>
        <p class="paragraph-link">
            <a class="link-home" href="manage-events.php">Retour à la gestion des épreuves</a>
        </p>
    </main>

    <footer>
        <figure>
            <img src="../../../img/logo-jo.png" alt="logo Jeux Olympiques 2024">
        </figure>
    </footer>
</body>

</html>