<?php
session_start();

// Vérification de la connexion
if (!isset($_SESSION['login'])) {
    header('Location: ../../../index.php');
    exit();
}

// Inclusion de la connexion à la base de données
require_once('../../../database/database.php');

// Variables pour stocker les messages
$message = '';
$erreur = '';

// Traitement des actions
try {
    // Modification d'un utilisateur
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'modifier') {
        // Préparation de la requête de mise à jour
        $requete = $connexion->prepare("UPDATE UTILISATEUR 
            SET nom_utilisateur = :nom, 
                prenom_utilisateur = :prenom, 
                login = :login 
            WHERE id_utilisateur = :id");
        
        $requete->execute([
            ':nom' => $_POST['nom_utilisateur'],
            ':prenom' => $_POST['prenom_utilisateur'],
            ':login' => $_POST['login'],
            ':id' => $_POST['id_utilisateur']
        ]);

        // Mise à jour du mot de passe si un nouveau mot de passe est fourni
        if (!empty($_POST['nouveau_password'])) {
            $mot_de_passe_hash = password_hash($_POST['nouveau_password'], PASSWORD_BCRYPT);
            
            $requete_password = $connexion->prepare("UPDATE UTILISATEUR 
                SET password = :password 
                WHERE id_utilisateur = :id");
            
            $requete_password->execute([
                ':password' => $mot_de_passe_hash,
                ':id' => $_POST['id_utilisateur']
            ]);
        }

        $message = "Utilisateur modifié avec succès";
    }

    // Suppression d'un utilisateur
    if (isset($_GET['action']) && $_GET['action'] === 'supprimer' && isset($_GET['id'])) {
        $requete = $connexion->prepare("DELETE FROM UTILISATEUR WHERE id_utilisateur = :id");
        $requete->execute([':id' => $_GET['id']]);

        $message = "Utilisateur supprimé avec succès";
    }

    // Récupération de la liste des utilisateurs
    $requete_liste = $connexion->query("SELECT * FROM UTILISATEUR");
    $utilisateurs = $requete_liste->fetchAll(PDO::FETCH_ASSOC);

} catch (PDOException $e) {
    $erreur = "Erreur : " . $e->getMessage();
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
    <title>Gestion des Utilisateurs - Jeux Olympiques - Los Angeles 2028</title>
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
        <h1>Liste des Utilisateurs</h1>
        
        <div class="action-buttons">
            <button onclick="window.location.href='add_user.php'">Ajouter un Utilisateur</button>
        </div>

        <?php 
        // Affichage des messages
        if (!empty($message)): ?>
            <div class="alert success"><?= htmlspecialchars($message) ?></div>
        <?php 
        endif; 
        
        if (!empty($erreur)): ?>
            <div class="alert error"><?= htmlspecialchars($erreur) ?></div>
        <?php endif; ?>

        <!-- Tableau des utilisateurs -->
        <?php if (!empty($utilisateurs)): ?>
            <table>
                <tr>
                    <th>Nom</th>
                    <th>Prénom</th>
                    <th>Login</th>
                    <th>Modifier</th>
                    <th>Supprimer</th>
                </tr>
                <?php foreach ($utilisateurs as $utilisateur): ?>
                    <tr>
                        <td><?= htmlspecialchars($utilisateur['nom_utilisateur']) ?></td>
                        <td><?= htmlspecialchars($utilisateur['prenom_utilisateur']) ?></td>
                        <td><?= htmlspecialchars($utilisateur['login']) ?></td>
                        <td>
                            <button onclick="openModifyUserForm(
                                <?= $utilisateur['id_utilisateur'] ?>, 
                                '<?= htmlspecialchars($utilisateur['nom_utilisateur']) ?>', 
                                '<?= htmlspecialchars($utilisateur['prenom_utilisateur']) ?>', 
                                '<?= htmlspecialchars($utilisateur['login']) ?>'
                            )">Modifier</button>
                        </td>
                        <td>
                            <button onclick="deleteUserConfirmation(<?= $utilisateur['id_utilisateur'] ?>)">Supprimer</button>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </table>
        <?php else: ?>
            <p>Aucun utilisateur trouvé.</p>
        <?php endif; ?>

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
        function openModifyUserForm(id_utilisateur, nom, prenom, login) {
            // Redirection vers une page de modification (à créer)
            window.location.href = 'modify-user.php?id=' + id_utilisateur + 
                '&nom=' + encodeURIComponent(nom) + 
                '&prenom=' + encodeURIComponent(prenom) + 
                '&login=' + encodeURIComponent(login);
        }

        function deleteUserConfirmation(id_utilisateur) {
            if (confirm("Êtes-vous sûr de vouloir supprimer cet utilisateur ?")) {
                window.location.href = '?action=supprimer&id=' + id_utilisateur;
            }
        }
    </script>
</body>
</html>