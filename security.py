# boutton de sécurité : en cas de vol ou quoi 
# ca force tt les ultisateurs a changer leur mdp
# les utlisateurs peuvent tjrs se connecter mais avant il doit changer le mdp


from datetime import datetime
from locale import currency

import bcrypt

from database import Database


class SecurityManager:
    @staticmethod
    def security_button():
      try:
            conn = Database.get_db_connection()
            cursor = conn.cursor()
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            current = Database.get_current_user()

            # Question 1 : il faut au moins 2 admins pour pouvoir confirmer
            cursor.execute("select count(id_number) from user_info where role ='admin'")
            if cursor.fetchone()[0] < 2:
                return False, "Il faut au moins 2 administrateurs.\nCréez d'abord un second admin."

            # Question 2 : y a-t-il une demande en attente (pas encore confirmée) ?
            cursor.execute("select id_request, requested_by from security_request where confirmed_by is null")
            pending = cursor.fetchone()

            # Question 3 : pas de demande -> c'est le 1er clic, on la crée
            if pending is None:
                cursor.execute("insert into security_request (requested_by, request_date) values (?, ?)",
                            (current, now))
                conn.commit()
                return True,"Demande enregistrée.\nUn autre administrateur doit confirmer."
            
            # Question 4 : il y a une demande. Qui l'a lancée ?
            id_request,requested_by = pending
            if requested_by == current:
                return False, "Vous avez déjà lancé cette demande.\nUn autre administrateur doit confirmer."
            # Un AUTRE admin confirme : on valide la demande...
            cursor.execute("update security_request set confirmed_by = ?, confirm_date = ? where id_request = ?",
                                (current, now, id_request))

            # ...et on met pour tt les utlisateurs comme ca il doit changer leur mdp 
            cursor.execute("update user_info set must_change_password = 1")
            conn.commit()
            return True, "Confirmé !\nTous les utilisateurs devront changer leur mot de passe à leur prochaine connexion."
      except Exception as e:
            print(f"erreur du bouton de sécurité: {e}")
            return False, "Erreur lors de l'opération."
      finally:
            if 'conn' in locals():
                cursor.close()
                conn.close()

    # Regarde l'étiquette de l'utilisateur connecté.
    # Renvoie True s'il doit changer son mot de passe, False sinon.
    @staticmethod
    def must_change_password():
        try:
            conn = Database.get_db_connection()
            cursor = conn.cursor()
            cursor.execute("select must_change_password from user_info where id_number = ?",
                           (Database.get_current_user(),))
            result = cursor.fetchone()
            # result vaut par exemple (1,) : on regarde la première case
            return result is not None and result[0] == 1
        except Exception as e:
            print(f"erreur de vérification du mot de passe: {e}")
            return False
        finally:
            if 'conn' in locals():
                cursor.close()
                conn.close()

    # Enregistre le nouveau mot de passe de l'utilisateur connecté
    # et enlève l'étiquette (must_change_password repasse à 0).
    # Renvoie (True ou False, message à afficher).
    @staticmethod
    def change_password(new_password):
        try:
            conn = Database.get_db_connection()
            cursor = conn.cursor()
            current = Database.get_current_user()

            # On récupère l'ancien mot de passe (haché) pour le comparer
            cursor.execute("select password_user from user_info where id_number = ?", (current,))
            old_hash = cursor.fetchone()[0]
            if isinstance(old_hash, str):
                old_hash = old_hash.encode('utf-8')

            # L'ancien mot de passe a peut-être été volé : on refuse de le réutiliser
            if bcrypt.checkpw(new_password.encode('utf-8'), old_hash):
                return False, "Le nouveau mot de passe doit être différent de l'ancien."

            # On hache le nouveau mot de passe, comme dans save_user
            new_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            # On l'enregistre et on enlève l'étiquette
            cursor.execute("update user_info set password_user = ?, must_change_password = 0 where id_number = ?",
                           (new_hash, current))
            conn.commit()
            return True, "Mot de passe changé avec succès."
        except Exception as e:
            print(f"erreur de changement de mot de passe: {e}")
            return False, "Erreur lors du changement de mot de passe."
        finally:
            if 'conn' in locals():
                cursor.close()
                conn.close()
    #il faut tjrs au moins 2 admins pour pouvoir confirmer.           
    @staticmethod
    def can_delete_user(id_number):
        try:
            conn = Database.get_db_connection()
            cursor = conn.cursor()

            # c qui la perosnne a supprimer
            cursor.execute("select role from user_info where id_number = ?", (id_number,))
            role = cursor.fetchone()[0]
            if role !="admin":
                return True,""

            #on compte il y a cmb d'admin
            cursor.execute("select count(id_number) from user_info where role = 'admin'")
            if cursor.fetchone()[0] <= 2:
                return False, ("Impossible de supprimer cet administrateur :\n"
                               "il doit toujours rester au moins 2 administrateurs\n"
                               "pour pouvoir utiliser le bouton de sécurité.")
            return True, ""
        except Exception as e:
            print(f"erreur de vérification de suppression: {e}")
            return False, "Erreur lors de la vérification."
        finally:
            if 'conn' in locals():
                cursor.close()
                conn.close()



