import pickle, pickletools, base64

serum = b"pickle.loads('<__main__.anti_pickle_serum object at 0x7efe20072850>')"

get = pickle.dumps(serum)
get = base64.b64encode(get)
let = base64.b64decode(get)
print(get)
print(let)