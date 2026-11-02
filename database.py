import sqlite3
import os.path
import bcrypt
from datetime import datetime

class Database:

    __isLoggIn = False
    __current_user = None
    __idConnexion = 0

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
        create_user_table_query = """create table if not exists userInfo(
            nameUser varchar(20) not null, 
            passwordUser varchar(100) not null, 
            role varchar(5) not null, 
            primary key(nameUser))"""
        cursor.execute(create_user_table_query)
        cursor.execute("insert into userInfo (nameUser, passwordUser, role) values (?, ?, ?)", 
            ('firstadmin', '$2b$12$9bKppilobc0wqkG9VnjZ3uHjOqbRNT8C8TCeckF/OodN49peqRl.W', 'admin'))
        conn.commit()


        #AMBZ 02
        #Date : 29/10/2026
        create_feature_table_query = """create table if not exists features(
            idFeature integer primary key autoincrement,
            nameFeature varchar(30) not null)"""

        cursor.execute(create_feature_table_query)
        cursor.execute("insert into features (nameFeature) values (?)", ('Générateur de Masques',))
        conn.commit()

        cursor.execute("insert into features (nameFeature) values (?)", ('Validateur Format IP',))
        conn.commit()

        cursor.execute("insert into features (nameFeature) values (?)", ('Analyseur de Propriétés',))
        conn.commit()

        cursor.execute("insert into features (nameFeature) values (?)", ('Masque de Classe',))
        conn.commit()

        cursor.execute("insert into features (nameFeature) values (?)", ('Réseau & Sous-Réseau',))
        conn.commit()

        cursor.execute("insert into features (nameFeature) values (?)", ('Découpe en Sous-Réseaux',))
        conn.commit()

        cursor.execute("insert into features (nameFeature) values (?)", ('Vérificateur Connexion',))
        conn.commit()

        cursor.execute("insert into features (nameFeature) values (?)", ('Infos Application',))
        conn.commit()

        create_connexion_query = """create table if not exists connexion(
            idConnexion integer primary key autoincrement, 
            dateLogin datetime not null, 
            dateLogout datetime)"""

        cursor.execute(create_connexion_query)
        conn.commit()

        cursor.execute("alter table connexion add column fkNameUser varchar(20) not null references userInfo(nameUser)")
        conn.commit()

        #AMBZ 02
        #Date : 01/11/2026
        #J'évite les alter table pour garder cette ordre précis. Sinon je devrais mettre les clés étrangères en dernier et c'est pas beau.
        create_used_table_query = """create table if not exists activities(
            fkIdFeature integer not null references features(idFeature),
            modifiedBy varchar(20) not null references userInfo(nameUser),
            dateOfUse datetime not null, 
            entry1 varchar(50), 
            entry2 varchar(50), 
            entry3 varchar(50), 
            entry4 varchar(50))"""

        cursor.execute(create_used_table_query)
        conn.commit()

        cursor.close()
        conn.close()      

    #AMBZ 02 
    #Date : 07/10/2026
    #During : 30minutes
    @staticmethod
    def check_login(username , password):
        try :
            conn = Database.get_db_connection()
            cursor = conn.cursor()

            #J'ai juste changé le %s à la fin de la requête query par ?
            query = "select passwordUser, role from userInfo where nameUser = ?"           
            cursor.execute(query, (username,))

            result = cursor.fetchone()
            hashed_from_db = result[0]
            role = result[1]

            if result:
                hashed_from_db = result[0]
                if isinstance(hashed_from_db, str):
                    hashed_from_db = hashed_from_db.encode('utf-8')
                
                if(bcrypt.checkpw(password.encode('utf-8'), hashed_from_db)):
                    Database.__current_user = username
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
    #Date : 07/10/2026
    @staticmethod
    def get_current_user():
        return Database.__current_user
                

    #AMBZ 02
    #Date : 07/10/2026
    #During : 2h
    @staticmethod
    def save_user(username, role, password):
        try : 
            conn = Database.get_db_connection()
            cursor = conn.cursor()
            
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
            cursor.execute("insert into userInfo (nameUser, role, passwordUser) values (?,?,?)", (username, role, hashed_password))
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
    #Date : 07/10/2026
    def get_users():
        conn = Database.get_db_connection()
        cursor = conn.cursor()
        query = "select nameUser, role from userInfo where nameUser not like ?"
        cursor.execute(query, (Database.get_current_user(),))
        return cursor.fetchall()  

    #AMBZ 02
    #Date : 07/10/2026
    def nb_users():
        conn = Database.get_db_connection()
        cursor = conn.cursor()
        query = "select count(nameUser) from userInfo where nameUser not like ?"
        cursor.execute(query, (Database.get_current_user(),))
        nb_users = cursor.fetchone()
        return nb_users[0]

    #AMBZ 02
    #Date : 01/11/2026
    def get_id_connexion():
        return Database.__idConnexion

    #AMBZ 02
    #Date : 28/10/2026
    #During : 10minutes
    @staticmethod
    def delete_user(user_to_delete):
        try:
            conn = Database.get_db_connection()
            cursor = conn.cursor()
            query = "delete from userInfo where nameUser like ?"
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
    def save_activity(entry1, entry2, entry3, entry4, idFeature):
        try:
            conn = Database.get_db_connection()
            cursor = conn.cursor()

            #Vérifier si l'identifiant de l'activité a déjà été enregistré.
            cursor.execute("select count(fkIdfeature) from activities where fkIdFeature = (?)", (idFeature,))
            countFeature = cursor.fetchone()[0]

            if countFeature != 0:
                cursor.execute("""update activities 
                    set modifiedBy = (?), dateOfUse = (?),  
                    entry1 = (?), entry2 = (?), entry3 = (?), entry4 = (?) where fkIdFeature = (?)""", 
                    (Database.get_current_user(), datetime.now().strftime("%Y-%m-%d %H:%M:%S"), entry1, entry2, entry3, entry4, idFeature))
                conn.commit()
            else:
                cursor.execute("""insert into activities values (?, ?, ?, ?, ?, ?, ?)""",
                    (idFeature, Database.get_current_user(), datetime.now().strftime("%Y-%m-%d %H:%M:%S"), entry1, entry2, entry3, entry4))
                conn.commit()

            # Afficher la db par dernière date de modification en utilisant une vue.
            cursor.execute("create view if not exists recent_activities as select * from activities order by dateOfUse desc")
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
                cursor.execute("""insert into connexion (dateLogin, dateLogout, fkNameUser) values (?, ?, ?)""",
                    (date_login, None, Database.get_current_user()))
                conn.commit()

                get_idconnexion_query = """select idConnexion from connexion where dateLogin = ? and fkNameUser like ?"""
                cursor.execute(get_idconnexion_query, (date_login, Database.get_current_user()))
                Database.__idConnexion = cursor.fetchone()[0]

            elif type == "logout":
                #Enregistrement de la date de déconnexion dans la table connexion.
                cursor.execute("update connexion set dateLogout = ? where idConnexion = ?", 
                    (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), Database.get_id_connexion()))
                conn.commit()

            return True
        except Exception as e:
            print(f"erreur d'enregistrement de la connexion': {e}")
            return False
        finally:
            if 'conn' in locals():
                cursor.close()
                conn.close()