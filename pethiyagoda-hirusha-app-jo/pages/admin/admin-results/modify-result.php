<?php
session_start();

// Vérifiez si l'utilisateur est connecté
if (!isset($_SESSION['login'])) {
    header('Location: ../../../index.php');
    exit();
}

require_once("../../../database/database.php");

// Vérifier si les IDs sont fournis dans l'URL
if (!isset($_GET['id_athlete']) || !isset($_GET['id_epreuve'])) {
    header('Location: manage-results.php');
    exit();
}

$id_athlete = $_GET['id_athlete'];
$id_epreuve = $_GET['id_epreuve'];

// Si le formulaire est soumis
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $nouveau_resultat = $_POST['resultat'];
    
    try {
        // Mettre à jour le résultat
        $query = "UPDATE PARTICIPER 
                 SET resultat = :resultat 
                 WHERE id_athlete = :id_athlete 
                 AND id_epreuve = :id_epreuve";
        
        $statement = $connexion->prepare($query);
        $statement->bindParam(':resultat', $nouveau_resultat);
        $statement->bindParam(':id_athlete', $id_athlete);
        $statement->bindParam(':id_epreuve', $id_epreuve);
        
        $statement->execute();
        
        // Rediriger vers la page de gestion des résultats
        header('Location: manage-results.php');
        exit();
    } catch (PDOException $e) {
        echo "Erreur : " . $e->getMessage();
    }
}

// Récupérer les informations actuelles
try {
    $query = "SELECT 
                a.nom_athlete,
                a.prenom_athlete,
                p.nom_pays,
                e.nom_epreuve,
                e.date_epreuve,
                e.heure_epreuve,
                s.nom_sport,
                pa.resultat
            FROM PARTICIPER pa
            JOIN ATHLETE a ON pa.id_athlete = a.id_athlete
            JOIN PAYS p ON a.id_pays = p.id_pays
            JOIN EPREUVE e ON pa.id_epreuve = e.id_epreuve
            JOIN SPORT s ON e.id_sport = s.id_sport
            WHERE pa.id_athlete = :id_athlete 
            AND pa.id_epreuve = :id_epreuve";

    $statement = $connexion->prepare($query);
    $statement->bindParam(':id_athlete', $id_athlete);
    $statement->bindParam(':id_epreuve', $id_epreuve);
    $statement->execute();
    
    $resultat = $statement->fetch(PDO::FETCH_ASSOC);

    if (!$resultat) {
        header('Location: manage-results.php');
        exit();
    }

} catch (PDOException $e) {
    echo "Erreur : " . $e->getMessage();
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
    <title>Modifier un Résultat - Jeux Olympiques 2028</title>
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
        <h1>Modifier un Résultat</h1>
        <form method="post" action="">
            <div class="form-group">
                <label for="athlete">Athlète :</label>
                <input type="text" id="athlete" value="<?php echo htmlspecialchars($resultat['prenom_athlete'] . ' ' . $resultat['nom_athlete']); ?>" readonly>
            </div>

            <div class="form-group">
                <label for="pays">Pays :</label>
                <input type="text" id="pays" value="<?php echo htmlspecialchars($resultat['nom_pays']); ?>" readonly>
            </div>

            <div class="form-group">
                <label for="sport">Sport :</label>
                <input type="text" id="sport" value="<?php echo htmlspecialchars($resultat['nom_sport']); ?>" readonly>
            </div>

            <div class="form-group">
                <label for="epreuve">Épreuve :</label>
                <input type="text" id="epreuve" value="<?php echo htmlspecialchars($resultat['nom_epreuve']); ?>" readonly>
            </div>

            <div class="form-group">
                <label for="date">Date et Heure :</label>
                <input type="text" id="date" value="<?php echo date('d/m/Y', strtotime($resultat['date_epreuve'])) . ' ' . $resultat['heure_epreuve']; ?>" readonly>
            </div>

            <div class="form-group">
                <label for="resultat">Résultat :</label>
                <input type="text" id="resultat" name="resultat" value="<?php echo htmlspecialchars($resultat['resultat']); ?>" required>
            </div>

            <div class="form-group">
                <input type="submit" value="Modifier le résultat">
            </div>
        </form>

        <p class="paragraph-link">
            <a class="link-home" href="manage-results.php">Retour à la gestion des résultats</a>
        </p>
    </main>

    <footer>
        <figure>
            <img src="../../../img/logo-jo.png" alt="logo Jeux Olympiques - Los Angeles 2028">
        </figure>
    </footer>
</body>

</html>