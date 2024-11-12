import pickle
import pickletools
import base64

class User:
    def __init__(self, name, age) -> None:
        self.name = name
        self.age = age
    def summary(self) -> str:
        print(f"{self.name} is {self.age} year(s) old.")
    
k = User('Khari', 24)

k.summary()  # Calls the summary() method from the User class

# Serializes the data as a string of bytes
serialized = pickle.dumps(k)
print(f"Serialized: {serialized}")

print(f'{k}')
new = pickle.loads(serialized)
print(f"Deserialized: {new}")
new.summary()


#cookie = base64.b64decode('KGRwMApTJ3NlcnVtJwpwMQpjY29weV9yZWcKX3JlY29uc3RydWN0b3IKcDIKKGNfX21haW5fXwphbnRpX3BpY2tsZV9zZXJ1bQpwMwpjX19idWlsdGluX18Kb2JqZWN0CnA0Ck50cDUKUnA2CnMu')
#print(cookie)

# Disassembles pickled class
#pickletools.dis(cookie)

# Deserializes pickled class
#k_d = pickle.loads(cookie)
#print(k_d)  # Prints the same thing as dumps
#k_d.summary()