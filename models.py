


class userSchema():
    def __init__(self, username, password, email, date, address, firstname, lastname, moveaddress, role, movehistory, verification_code=None):
        self.username = username
        self.password = password
        self.email = email
        self.date = date
        self.address = None
        self.moveaddress = None
        self.firstname = firstname
        self.lastname = lastname
        self.verified = False
        self.verification_code = verification_code
        self.role = role
        self.movehistory = movehistory
class Address1():
    def __init__(self, address, city, state, zip):
        self.address = address
        self.city = city
        self.state = state
        self.zip = zip
class MoveAddress1():
    def __init__(self, address, city, state, zip, date, reason, verification_code=None):
        self.address = address
        self.city = city
        self.state = state
        self.zip = zip
        self.date = date
        self.reason = reason
        self.verified = False
        self.verification_code = verification_code
        

    # def jsonstringify(self):
    #     jsondata = {}
    #     str1 = "username"
    #     str2 = "password"
    #     str3 = "email"
    #     str4 = "date"
    #     jsondata = {}
    #     jsondata[str1] = self.username
    #     jsondata[str2] = self.password
    #     jsondata[str3] = self.email
    #     jsondata[str4] = self.date
        
        





