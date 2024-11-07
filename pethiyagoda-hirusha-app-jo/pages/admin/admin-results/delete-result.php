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
    $_SESSION['error'] = "Paramètres manquants pour la suppression.";
    header('Location: manage-results.php');
    exit();
}

$id_athlete = $_GET['id_athlete'];
$id_epreuve = $_GET['id_epreuve'];

try {
    // Commencer une transaction
    $connexion->beginTransaction();

    // Récupérer les informations du résultat avant la suppression
    $query_select = "SELECT a.prenom_athlete, a.nom_athlete, e.nom_epreuve, pa.resultat
                     FROM PARTICIPER pa
                     JOIN ATHLETE a ON pa.id_athlete = a.id_athlete
                     JOIN EPREUVE e ON pa.id_epreuve = e.id_epreuve
                     WHERE pa.id_athlete = :id_athlete AND pa.id_epreuve = :id_epreuve";
    $statement_select = $connexion->prepare($query_select);
    $statement_select->bindParam(':id_athlete', $id_athlete, PDO::PARAM_INT);
    $statement_select->bindParam(':id_epreuve', $id_epreuve, PDO::PARAM_INT);
    $statement_select->execute();
    $result_info = $statement_select->fetch(PDO::FETCH_ASSOC);

    if (!$result_info) {
        throw new Exception("Résultat non trouvé.");
    }

    // Supprimer le résultat
    $query_delete = "DELETE FROM PARTICIPER WHERE id_athlete = :id_athlete AND id_epreuve = :id_epreuve";
    $statement_delete = $connexion->prepare($query_delete);
    $statement_delete->bindParam(':id_athlete', $id_athlete, PDO::PARAM_INT);
    $statement_delete->bindParam(':id_epreuve', $id_epreuve, PDO::PARAM_INT);
    $statement_delete->execute();

    // Valider la transaction
    $connexion->commit();

    // Message de succès
    $_SESSION['success'] = "Le résultat de " . $result_info['prenom_athlete'] . " " . $result_info['nom_athlete'] . 
                           " pour l'épreuve '" . $result_info['nom_epreuve'] . "' a été supprimé avec succès.";

} catch (Exception $e) {
    // En cas d'erreur, annuler la transaction
    $connexion->rollBack();
    $_SESSION['error'] = "Erreur lors de la suppression : " . $e->getMessage();
}

// Rediriger vers la page de gestion des résultats
header('Location: manage-results.php');
exit();
?>