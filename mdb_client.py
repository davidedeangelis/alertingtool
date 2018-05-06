from pymongo import MongoClient

class MongoDBClient():

    def __init__(self, cluster_name = None, username = None, password = None, db_name = None):

        if cluster_name is None or username is None or password is None or db_name is None:
            return None
        else:
            self._connection = MongoClient("mongodb+srv://{}:{}@{}".format(username, password, cluster_name))
            self._db = self._connection[str(db_name)]

    @property
    def db(self):
        return self._db

    def collection(self, coll_name):
        return self.db[coll_name]
