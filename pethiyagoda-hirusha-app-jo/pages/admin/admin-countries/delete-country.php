<?php
session_start();

// Vérifiez si l'utilisateur est connecté
if (!isset($_SESSION['login'])) {
    header('Location: ../../../index.php');
    exit();
}

// Vérifier si l'ID du pays est fourni
if (!isset($_GET['id_pays'])) {
    $_SESSION['error'] = "ID du pays non spécifié.";
    header('Location: manage-countries.php');
    exit();
}

$id_pays = $_GET['id_pays'];

// Fonction pour vérifier le token CSRF
function checkCSRFToken() {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            die('Token CSRF invalide.');
        }
    }
}

// Générer un token CSRF si ce n'est pas déjà fait
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

require_once("../../../database/database.php");

// Traitement de la suppression
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    checkCSRFToken();

    try {
        // Vérifier si le pays est utilisé dans d'autres tables
        $query = "SELECT COUNT(*) FROM ATHLETE WHERE id_pays = ?";
        $statement = $connexion->prepare($query);
        $statement->execute([$id_pays]);
        $count = $statement->fetchColumn();

        if ($count > 0) {
            $_SESSION['error'] = "Impossible de supprimer ce pays car il est associé à des athlètes.";
        } else {
            // Supprimer le pays
            $query = "DELETE FROM PAYS WHERE id_pays = ?";
            $statement = $connexion->prepare($query);
            $statement->execute([$id_pays]);

            $_SESSION['success'] = "Pays supprimé avec succès.";
        }
        header('Location: manage-countries.php');
        exit();
    } catch (PDOException $e) {
        $_SESSION['error'] = "Erreur lors de la suppression du pays : " . $e->getMessage();
        header('Location: manage-countries.php');
        exit();
    }
}

// Récupérer les informations du pays
try {
    $query = "SELECT * FROM PAYS WHERE id_pays = ?";
    $statement = $connexion->prepare($query);
    $statement->execute([$id_pays]);
    $pays = $statement->fetch(PDO::FETCH_ASSOC);

    if (!$pays) {
        $_SESSION['error'] = "Pays non trouvé.";
        header('Location: manage-countries.php');
        exit();
    }
} catch (PDOException $e) {
    $_SESSION['error'] = "Erreur lors de la récupération des informations du pays : " . $e->getMessage();
    header('Location: manage-countries.php');
    exit();
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
    <title>Supprimer un Pays - Jeux Olympiques 2024</title>
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
        <h1>Supprimer un Pays</h1>
        
        <?php
        if (isset($_SESSION['error'])) {
            echo '<div class="error-message">' . $_SESSION['error'] . '</div>';
            unset($_SESSION['error']);
        }
        ?>

        <p>Êtes-vous sûr de vouloir supprimer le pays suivant ?</p>
        <p><strong><?php echo htmlspecialchars($pays['nom_pays']); ?></strong></p>

        <form method="post" action="">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            
            <div class="form-buttons">
                <input type="submit" value="Confirmer la suppression">
            </div>
        </form>

        <p class="paragraph-link">
            <a class="link-home" href="manage-countries.php">Retour à la gestion des pays</a>
        </p>
    </main>

    <footer>
        <figure>
            <img src="../../../img/logo-jo.png" alt="logo Jeux Olympiques 2024">
        </figure>
    </footer>
</body>

</html>