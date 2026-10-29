import sqlite3
import os.path
import bcrypt

class Database:

    __isLoggIn = False
    __current_user = None

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

        create_table_query = """create table if not exists userInfo(
            nameUser varchar(100) not null, 
            passwordUser varchar(100) not null, 
            role varchar(100) not null default ('user'), 
            primary key (nameUser))"""
        cursor.execute(create_table_query)
        cursor.execute("insert into userInfo values (?,?,?)", 
            ('firstadmin', '$2b$12$9bKppilobc0wqkG9VnjZ3uHjOqbRNT8C8TCeckF/OodN49peqRl.W', 'admin'))
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

    def get_users():
        conn = Database.get_db_connection()
        cursor = conn.cursor()
        query = "select nameUser, role from userInfo where nameUser not like ?"
        cursor.execute(query, (Database.get_current_user(),))
        return cursor.fetchall()  
    
    def nb_users():
        conn = Database.get_db_connection()
        cursor = conn.cursor()
        query = "select count(nameUser) from userInfo where nameUser not like ?"
        cursor.execute(query, (Database.get_current_user(),))
        nb_users = cursor.fetchone()
        return nb_users[0]

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