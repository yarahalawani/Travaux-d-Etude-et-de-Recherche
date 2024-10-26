architecture software / hardware
reverse proxy

modèle simplifié

N = not available
B = bad data
M = malware

sens = capteur
front = partie exposée
entouré en jaune/noir = partie du kernel

un automate par composant software
hardware disparait du modèle UPPAAL
application compromise => peut attaquer d'autres applications
systèmes permissifs (droits plus importants que nécessaires)
hardware => règles de routage

=> Lire le papier associé

point entrée attaquant

ExtHack dans état malware

input (prédécesseurs) : 
-> graphe de visiblité : définit quels sont les composants prédécesseurs
chaque composant peut être attaqué sur différents ports (rôles)

différents coûts d'attaque selon états des prédécesseurs

transitions définies dans le papier

t3 => de F à M => possible si un des prédécesseurs est dans l'état M sur n'importe quel rôle

pour franchir transition => conditions de franchissement

rôles obligatoires / optionnels (peut fonctionner avec quelques rôles optionnels non fonctionnels)

coût des transitions

fichier json -> description du modèle

1 seule transition dans un automate par transition

clés de sécurité

chq transition correspond à un coût

risk assessment / analyse des risques

niveau de risque acceptable selon les dommages causés

combien coûte la perte d'un système

coût important => probabilité minimale
coût faible => probabilité importante


contacter l'autre groupe qui a étudié la question


séparer sélection transitions accessibles et choix de la transition
