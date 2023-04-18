# TD1imadsamaha
Q1 :Quelle est le nom de l'algorithme de chiffrement ? Est-il robuste et pourquoi ?
L'algorithme de chiffrement utilisé dans le code fourni est appelé XOR (ou chiffrement par ou eXclusive). Cet algorithme de chiffrement est simple et rapide a implementer, car il utilise une operation bit a bit sur les donnees a chiffrer. Cette algorithme n'est pas robuste, et voici quelques raisons:
_Faible taille de cle: la cle utilisee dans l'algotithme de chiffrement XOR est une sequence de bits de longueur egale ou superieur au texte en clair. cela signifie que l'attanquant peut essayer toutes les combinaisons possibles de la cle pour retrouver le texte en clair.
_Manque de diffusion: XOR ne diffuse pas les caracteristiques du texte en clair dans le texte chiffre, cela peut rendre l'algorithme de chiffrement XOR vulnerable a certaines attaques cryptanalytiques.
_Sensibilite a la repetition de motifs: Si le texte en clair contient des motifs répétitifs, le texte chiffré obtenu avec l'algorithme de chiffrement XOR peut également présenter ces motifs. Cela peut faciliter la déduction de certaines informations sur le texte en clair par des attaquants, même sans connaître la clé de chiffrement.

Q2:Pourquoi ne pas hacher le sel et la clef directement ? Et avec un hmac ?
Hacher le sel et la clé directement n'est généralement pas une bonne pratique en matière de sécurité.Le sel et la clé sont utilisés pour protéger le processus de hachage et de cryptage, et leur mauvaise manipulation peut compromettre la sécurité du système.
Utiliser un algorithme de hachage basé sur un HMAC peut offrir une sécurité supplémentaire en ajoutant une couche de vérification d'intégrité des données. Un HMAC utilise une clé secrète pour calculer un code d'authentification de message basé sur la donnée d'entrée et la clé secrète, ce qui permet de vérifier l'intégrité de la donnée lors de la vérification.

Q3:Pourquoi il est préférable de vérifier qu'un fichier token.bin n'est pas déjà présent ?
Vérifier si un fichier token.bin est déjà présent avant de le créer peut contribuer à éviter les conflits, économiser des ressources, assurer la cohérence et améliorer la performance de notre système. Il est donc généralement considéré comme une bonne pratique en matière de développement de logiciels ou de gestion de fichiers.

Q4:Comment vérifier que la clef la bonne ?
Par comparaison directe, on peut comparer la clé candidate avec une clé dérivée a partir du sel pour vérifier si elles sont identiques. On compare cette clé dérivée avec le token stocké dans le self._token et si elle sont identiques alors c'est bon.
