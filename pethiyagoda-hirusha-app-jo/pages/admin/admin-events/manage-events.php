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
    <title>Liste des Épreuves - Jeux Olympiques - Los Angeles 2028</title>
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
        <h1>Liste des Épreuves</h1>
        <div class="action-buttons">
            <button onclick="openAddEpreuveForm()">Ajouter une Épreuve</button>
        </div>
        
        <!-- Tableau des épreuves -->
        <?php
        require_once("../../../database/database.php");

        try {
            // Requête pour récupérer la liste des épreuves avec les informations associées
            $query = "SELECT e.id_epreuve, e.nom_epreuve, e.date_epreuve, e.heure_epreuve, 
                             s.nom_sport, l.nom_lieu 
                      FROM EPREUVE e
                      JOIN SPORT s ON e.id_sport = s.id_sport
                      JOIN LIEU l ON e.id_lieu = l.id_lieu
                      ORDER BY e.date_epreuve, e.heure_epreuve";
            
            $statement = $connexion->prepare($query);
            $statement->execute();

            // Vérifier s'il y a des résultats
            if ($statement->rowCount() > 0) {
                echo "<table>
                        <tr>
                            <th>Épreuve</th>
                            <th>Sport</th>
                            <th>Date</th>
                            <th>Heure</th>
                            <th>Lieu</th>
                            <th>Modifier</th>
                            <th>Supprimer</th>
                        </tr>";

                // Afficher les données dans un tableau
                while ($row = $statement->fetch(PDO::FETCH_ASSOC)) {
                    echo "<tr>";
                    echo "<td>" . htmlspecialchars($row['nom_epreuve']) . "</td>";
                    echo "<td>" . htmlspecialchars($row['nom_sport']) . "</td>";
                    echo "<td>" . date('d/m/Y', strtotime($row['date_epreuve'])) . "</td>";
                    echo "<td>" . date('H:i', strtotime($row['heure_epreuve'])) . "</td>";
                    echo "<td>" . htmlspecialchars($row['nom_lieu']) . "</td>";
                    echo "<td><button onclick='openModifyEpreuveForm({$row['id_epreuve']})'>Modifier</button></td>";
                    echo "<td><button onclick='deleteEpreuveConfirmation({$row['id_epreuve']})'>Supprimer</button></td>";
                    echo "</tr>";
                }

                echo "</table>";
            } else {
                echo "<p>Aucune épreuve trouvée.</p>";
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

    <script>
        function openAddEpreuveForm() {
            window.location.href = 'add-events.php';
        }

        function openModifyEpreuveForm(id_epreuve) {
            window.location.href = 'modify-events.php?id_epreuve=' + id_epreuve;
        }

        function deleteEpreuveConfirmation(id_epreuve) {
            if (confirm("Êtes-vous sûr de vouloir supprimer cette épreuve ?")) {
                window.location.href = 'delete-events.php?id_epreuve=' + id_epreuve;
            }
        }
    </script>
</body>

</html>