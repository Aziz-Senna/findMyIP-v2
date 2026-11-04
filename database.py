import sqlite3
import os.path
import bcrypt
import random
from datetime import datetime

class Database:

    __isLoggIn = False
    __current_idnumber = None
    __id_connexion = 0

    #AMBZ 02
    #Date : 06/10/2026
    #During : 30minutes
    @staticmethod
    def get_db_connection():
        if (os.path.isfile("FINDMYIP.db") == False):
            Database.create_db()
        Database.__isLoggIn = True
        return sqlite3.connect("FINDMYIP.db")

    #AMBZ 02
    #Date : 06/10/2026
    #During : 10minutes
    @staticmethod
    def create_db():
        conn = sqlite3.connect("FINDMYIP.db")
        cursor = conn.cursor()

        #AMBZ 02
        #Date : 29/10/2026
        #Update of the table
        create_user_table_query = """create table if not exists user_info(
            id_number varchar(5) not null,
            username varchar(20) not null, 
            password_user varchar(100) not null, 
            role varchar(5) not null, 
            primary key(id_number))"""
        cursor.execute(create_user_table_query)
        cursor.execute("insert into user_info values (?, ?, ?, ?)", 
            ('00.00', 'firstadmin', '$2b$12$9bKppilobc0wqkG9VnjZ3uHjOqbRNT8C8TCeckF/OodN49peqRl.W', 'admin'))
        conn.commit()

        create_connexion_query = """create table if not exists connexion(
            id_connexion integer primary key autoincrement, 
            date_login datetime not null, 
            date_logout datetime)"""

        cursor.execute(create_connexion_query)
        conn.commit()

        cursor.execute("alter table connexion add column fk_id_number varchar(5) not null references user_info(id_number)")
        conn.commit()

        #AMBZ 02
        #Date : 01/11/2026
        #J'évite les alter table pour garder cette ordre précis. Sinon je devrais mettre les clés étrangères en dernier et c'est pas beau.
        create_used_table_query = """create table if not exists activities(
            modified_by varchar(5) not null references user_info(id_number),
            name_feature varchar(30) not null,
            date_of_use datetime not null,
            entry1 varchar(50),
            entry2 varchar(50),
            entry3 varchar(50),
            entry4 varchar(50))"""

        cursor.execute(create_used_table_query)
        conn.commit()

        #YAAL 01
        #Date : 03/11/2026
        # Tâche 3 : table d'adressage validée par la prof.
        # On garde la "recette" de chaque découpe, pas la liste des sous-réseaux.
        create_addressing_table_query = """create table if not exists addressing_table(
            id_addressing integer primary key autoincrement,
            modified_by varchar(5) not null references user_info(id_number),
            modified_date datetime not null,
            network varchar(15) not null,
            mask varchar(15) not null,
            nb_subnets integer not null,
            max_hosts integer not null)"""
        cursor.execute(create_addressing_table_query)
        conn.commit()
        cursor.close()
        conn.close()    

    #AMBZ 02
    #Date : 07/10/2026
    # Retourne le martricule de l'utilisateur
    @staticmethod
    def get_current_user():
        return Database.__current_idnumber

    #AMBZ 02
    #Date : 03/11/2026
    @staticmethod
    # Retourne le nom d'utilisateur
    def get_current_username():
        try : 
            conn = Database.get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("select username from user_info where id_number = (?)", (Database.get_current_user(),))
            return cursor.fetchone()[0]
        except Exception as e:
            print(f"erreur d'enregistrement: {e}")
            return False
        finally:
            if 'conn' in locals() and conn.cursor():
                #Il fallait inverser l'ordre de fermeture entre conn et cursor.
                cursor.close()
                conn.close() 
                

    #AMBZ 02
    #Date : 07/10/2026
    def get_users():
        conn = Database.get_db_connection()
        cursor = conn.cursor()
        query = "select id_number, username, role from user_info where id_number not like ?"
        cursor.execute(query, (Database.get_current_user(),))
        return cursor.fetchall()  

    #AMBZ 02
    #Date : 07/10/2026
    def nb_users():
        conn = Database.get_db_connection()
        cursor = conn.cursor()
        query = "select count(username) from user_info where id_number not like ?"
        cursor.execute(query, (Database.get_current_user(),))
        nb_users = cursor.fetchone()
        return nb_users[0]

    #AMBZ 02
    #Date : 01/11/2026
    def get_id_connexion():
        return Database.__id_connexion

    #AMBZ 02
    #Date : 03/11/2026
    #Créer un matricule pour le nouvelle utilisateur
    @staticmethod
    def create_id_number():
        id_number = random.randrange(pow(9, 5) + 1) #00.00 est reservé pour le firstadmin
        id_number = str(id_number)
        # Avoir le format XX.XX
        id_number = id_number[:2] + "." + id_number[-2:]
        try: 
            conn = Database.get_db_connection()
            cursor = conn.cursor()
            check_id_number_exists_query = "select count(id_number) from user_info where id_number = (?)"
            cursor.execute(check_id_number_exists_query, (id_number,))
            while cursor.fetchone()[0] != 0:
                id_number = random.randrange(pow(9, 5) + 1) #00.00 est reservé pour le firstadmin
                id_number = str(id_number)
                id_number = id_number[:2] + "." + id_number[-2:]
            return id_number
        except Exception as e:
            print(f"erreur dans la création de matricule: {e}")
            return False
        finally:
            if 'conn' in locals() and conn.cursor():
                cursor.close()
                conn.close()


    #AMBZ 02
    #Date : 07/10/2026
    #During : 2h
    @staticmethod
    def save_user(id_number, username, role, password):
        try : 
            conn = Database.get_db_connection()
            cursor = conn.cursor()
            
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
            cursor.execute("insert into user_info values (?,?,?,?)", (id_number, username, hashed_password, role))
            conn.commit()
            return True
        except Exception as e:
            print(f"erreur d'enregistrement: {e}")
            return False
        finally:
            if 'conn' in locals() and conn.cursor():
                #Il fallait inverser l'ordre de fermeture entre conn et cursor.
                cursor.close()
                conn.close()

    #AMBZ 02
    #Date : 28/10/2026
    #During : 10minutes
    @staticmethod
    def delete_user(user_to_delete):
        try:
            conn = Database.get_db_connection()
            cursor = conn.cursor()
            query = "delete from user_info where id_number like ?"
            cursor.execute(query, (Database.get_users()[user_to_delete][0],))
            conn.commit()
            return True
        except Exception as e:
            print(f"erreur de suppression: {e}")
            return False
        finally:
            if 'conn' in locals() and conn.cursor():
                #Il fallait inverser l'ordre de fermeture entre conn et cursor.
                cursor.close()
                conn.close() 

    #AMBZ 02 
    #Date : 07/10/2026
    #During : 30minutes
    @staticmethod
    def check_login(id_number , password):
        try :
            conn = Database.get_db_connection()
            cursor = conn.cursor()

            #J'ai juste changé le %s à la fin de la requête query par ?
            query = "select password_user, role from user_info where id_number = (?)"           
            cursor.execute(query, (id_number,))

            result = cursor.fetchone()
            hashed_from_db = result[0]
            role = result[1]

            if result:
                hashed_from_db = result[0]
                if isinstance(hashed_from_db, str):
                    hashed_from_db = hashed_from_db.encode('utf-8')
                
                if(bcrypt.checkpw(password.encode('utf-8'), hashed_from_db)):
                    Database.__current_idnumber = id_number
                    return role                
            return False
        except Exception as e:
            print(f"erreur de connexion: {e}")
            return False
        finally:
            if 'conn' in locals() and conn.cursor():
                #Il fallait inverser l'ordre de fermeture entre conn et cursor.
                cursor.close()
                conn.close()       

    #AMBZ 02
    #Date : 13/10/2026
    #During : 10minutes
    @staticmethod
    def check_logout():
        if(Database.__isLoggIn == False):
           return False
        Database.__isLoggIn = False
        return True

    #YAAL 01
    #Date : 02/11/2026    
    @staticmethod
    # Les entry sauvegardent ce que l'utilisateur entre, et non les résultats.
    def save_activity(entry1, entry2, entry3, entry4, name_feature):
        try:
            conn = Database.get_db_connection()
            cursor = conn.cursor()

            #Vérifier si le nom de l'activité a déjà été enregistré.
            cursor.execute("select count(name_feature) from activities where name_feature = (?)", (name_feature,))
            countFeature = cursor.fetchone()[0]

            if countFeature != 0:
                cursor.execute("""update activities 
                    set modified_by = (?), name_feature = (?), date_of_use = (?),  
                    entry1 = (?), entry2 = (?), entry3 = (?), entry4 = (?) where name_feature = (?)""", 
                    (Database.get_current_user(), name_feature, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), entry1, entry2, entry3, entry4))
                conn.commit()
            else:
                cursor.execute("""insert into activities values (?, ?, ?, ?, ?, ?, ?)""",
                    (Database.get_current_user(), name_feature, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), entry1, entry2, entry3, entry4))
                conn.commit()

            # Afficher la table activities par dernière date de modification en utilisant une vue.
            cursor.execute("create view if not exists recent_activities as select * from activities order by date_of_use desc")
            conn.commit()
            return True
        except Exception as e:
            print(f"erreur d'enregistrement de l'activité': {e}")
            return False
        finally:
            if 'conn' in locals():
                cursor.close()
                conn.close()

    #AMBZ 02
    #Date : 01/11/2026
    @staticmethod
    def save_connexion(type):
        try:
            conn = Database.get_db_connection()
            cursor = conn.cursor()  

            if type == "login":
                #Récupérer la date de connexion.
                date_login = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                cursor.execute("""insert into connexion (date_login, date_logout, fk_id_number) values (?, ?, ?)""",
                    (date_login, None, Database.get_current_user()))
                conn.commit()

                get_id_connexion_query = """select id_connexion from connexion where date_login = ? and fk_id_number like ?"""
                cursor.execute(get_id_connexion_query, (date_login, Database.get_current_user()))
                Database.__id_connexion = cursor.fetchone()[0]

            elif type == "logout":
                #Enregistrement de la date de déconnexion dans la table connexion.
                cursor.execute("update connexion set date_logout = ? where id_connexion = ?", 
                    (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), Database.get_id_connexion()))
                conn.commit()

            # Afficher la table connexion par dernière date de déconnexion en utilisant une vue.
            cursor.execute("create view if not exists recent_connexion as select * from connexion order by date_logout desc")
            conn.commit()

            return True
        except Exception as e:
            print(f"erreur d'enregistrement de la connexion': {e}")
            return False
        finally:
            if 'conn' in locals():
                cursor.close()
                conn.close()
    #YAAL 01
    #Date : 03/11/2026
    # Tâche 3 : écrit une ligne (la "recette" d'une découpe) dans la table d'adressage.
    # On ne stocke que ce qu'il faut pour regénérer la découpe, pas la liste des sous-réseaux.
    # Renvoie True si l'enregistrement a réussi, False sinon.
    @staticmethod
    def save_subnetting(network, mask, nb_subnets, max_hosts):
        try:
            conn = Database.get_db_connection()
            cursor = conn.cursor()
            # Les "?" sont remplacés dans l'ordre par les valeurs du tuple (protection contre l'injection SQL).
            # id_addressing se remplit tout seul (autoincrement).
            cursor.execute("""insert into addressing_table
                (network, mask, nb_subnets, max_hosts, modified_by, modified_date)
                values (?, ?, ?, ?, ?, ?)""",
                (network, mask, nb_subnets, max_hosts, Database.get_current_user(),
                 datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
            return True
        except Exception as e:
            print(f"erreur d'enregistrement de la découpe: {e}")
            return False
        finally:
            # Dans tous les cas (réussite ou erreur), on ferme la connexion
            if 'conn' in locals():
                cursor.close()
                conn.close()