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
    <title>Gestion des Résultats - Jeux Olympiques - Los Angeles 2028</title>
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
        <h1>Gestion des Résultats</h1>
        <div class="action-buttons">
            <a href="add-result.php" class="button">Ajouter un Résultat</a>
        </div>

        <?php
        require_once("../../../database/database.php");

        try {
            $query = "SELECT 
                        e.date_epreuve,
                        e.heure_epreuve,
                        e.nom_epreuve,
                        a.nom_athlete,
                        a.prenom_athlete,
                        p.nom_pays,
                        pa.resultat,
                        pa.id_athlete,
                        pa.id_epreuve
                    FROM 
                        EPREUVE e
                        INNER JOIN PARTICIPER pa ON e.id_epreuve = pa.id_epreuve
                        INNER JOIN ATHLETE a ON pa.id_athlete = a.id_athlete
                        INNER JOIN PAYS p ON a.id_pays = p.id_pays
                    ORDER BY 
                        e.date_epreuve, e.heure_epreuve";
            
            $statement = $connexion->prepare($query);
            $statement->execute();

            if ($statement->rowCount() > 0) {
                echo "<table>
                        <tr>
                            <th>Date</th>
                            <th>Heure</th>
                            <th>Épreuve</th>
                            <th>Athlète</th>
                            <th>Pays</th>
                            <th>Résultat</th>
                            <th>Modifier</th>
                            <th>Supprimer</th>
                        </tr>";

                while ($row = $statement->fetch(PDO::FETCH_ASSOC)) {
                    echo "<tr>";
                    echo "<td>" . date('d/m/Y', strtotime($row['date_epreuve'])) . "</td>";
                    echo "<td>" . $row['heure_epreuve'] . "</td>";
                    echo "<td>" . htmlspecialchars($row['nom_epreuve']) . "</td>";
                    echo "<td>" . htmlspecialchars($row['prenom_athlete']) . " " . htmlspecialchars($row['nom_athlete']) . "</td>";
                    echo "<td>" . htmlspecialchars($row['nom_pays']) . "</td>";
                    echo "<td>" . htmlspecialchars($row['resultat']) . "</td>";
                    echo "<td><a href='modify-result.php?id_athlete=" . $row['id_athlete'] . "&id_epreuve=" . $row['id_epreuve'] . "' class='button'>Modifier</a></td>";
                    echo "<td><a href='delete-result.php?id_athlete=" . $row['id_athlete'] . "&id_epreuve=" . $row['id_epreuve'] . "' class='button' onclick='return confirm(\"Êtes-vous sûr de vouloir supprimer ce résultat ?\");'>Supprimer</a></td>";
                    echo "</tr>";
                }

                echo "</table>";
            } else {
                echo "<p>Aucun résultat trouvé.</p>";
            }
        } catch (PDOException $e) {
            echo "Erreur : " . htmlspecialchars($e->getMessage());
        }
        ?>

        <p class="paragraph-link">
            <a class="link-home" href="../admin.php">Accueil administration</a>
        </p>
    </main>

    <footer>
        <figure>
            <img src="../../../img/logo-jo.png" alt="logo Jeux Olympiques - Los Angeles 2028">
        </figure>
    </footer>
</body>

</html>