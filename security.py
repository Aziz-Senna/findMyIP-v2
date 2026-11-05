# boutton de sécurité : en cas de vol ou quoi 
# ca force tt les ultisateurs a changer leur mdp
# les utlisateurs peuvent tjrs se connecter mais avant il doit changer le mdp


from datetime import datetime
from locale import currency

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
      



      

      