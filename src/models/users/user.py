import uuid
import src.models.users.errors as UserErrors
from src.common.database import Database
from src.common.utils import Utils
from src.models.alerts.alert import Alert
import src.models.users.constants as UserCOnstants


class User(object):
    def __init__(self, email, password, _id=None):
        self.email = email
        self.password = password
        self._id = uuid.uuid4().hex if _id is None else _id

    def __repr__(self):
        return "User {}".format(self.email)

    @staticmethod
    def is_login_valid(email, password):
        """
        This method verifies that email / password combo is valid.
        Check if the email exist and if the password associate is correct
        :param email: The user's email
        :param password: A sha12 hashed password
        :return:True if valid, False if wrong
        """
        user_data = Database.find_one(UserCOnstants.COLLECTION, {"email": email})
        if user_data is None:
            # email not exist
            raise UserErrors.UserNotExistError("Your user does not exist")
        if not Utils.check_hashed_password(password, user_data['password']):
            # tell user password is wrong
            raise UserErrors.IncorrectPasswordError("Your password is wrong")
        return True

    @staticmethod
    def register_user(email, password):
        """
        This method register a user.
        Password already comes hashed as sha-512
        :param email:
        :param password:
        :return: True if registered successfully
        """
        user_data = Database.find_one(UserCOnstants.COLLECTION, {"email": email})

        if user_data is not None:
            #tell user is already exist
            raise UserErrors.UserAlreadyRegisteredError("Try another email adress")
        if not Utils.email_is_valid(email):
            #tell user that emails has invalid format
            raise UserErrors.InvalidEmailError("The format doesn't match the email pattenr")

        User(email, Utils.hash_password(password)).save_to_db()
        return True

    def save_to_db(self):
        Database.insert(UserCOnstants.COLLECTION, self.json())

    def json(self):
        return {
            "_id": self._id,
            "email": self.email,
            "password": self.password
        }

    @classmethod
    def find_by_email(cls, email):
        return cls(**Database.find_one(UserCOnstants.COLLECTION, {"email": email}))

    def get_alerts(self):
        return Alert.find_by_user_email(self.email)
