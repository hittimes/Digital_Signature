'''
data: 2018-5-15
author: huyuanzhi
'''


import hashlib
import rsa

CA = {}
'''
函数功能: 对一段字符串进行签名
参数: str是需要签名的字符串，privk是私钥
返回值: crypto是密文
'''
def rsaEncrypt(str,privk):
    # 明文编码格式
    content = str.encode('utf-8')
    # 私钥签名
    crypto = rsa.sign(content,privk,'SHA-1')
    return crypto
'''
函数功能: 对一段字符串和密文进行签名校验
参数: mess是传过来的字符串(消息)，signa是密文，pubk是公钥
返回值: 校验是否成功
'''
def rsaDecrypt(mess, signa, pubk):
    # 公钥验证
    try:
        rsa.verify(mess.encode(),signa,pubk)
    except rsa.VerificationError:
        result = False
    else:
        result = True
    return result

def applyKey(name,pubk):
    #向CA/RA申请证书，我这里简化了，没做任何事，就是在CA里保存了一下
    CA[name] = pubk

class User:
    def __init__(self,name):
        self.name = name
        self.crypto = ''
        # 生成公钥、私钥
        (self.pubkey,self.privkey) = rsa.newkeys(512)
        applyKey(self.name,self.pubkey)
    #签名
    def sign(self,str):
        self.crypto = rsaEncrypt(hashlib.md5((str + self.name).encode()).hexdigest(),self.privkey)
        print("密文: {0}".format(self.crypto))
        return self.crypto
    #验证别人的签名
    def check(self,str,user,crypto):
        if user.name not in CA:
            print("该用户没有申请证书")
        else:
            pubk = CA[user.name]
            if rsaDecrypt(hashlib.md5((str+user.name).encode()).hexdigest(),crypto,pubk):
                print("{0}的签名验证成功！".format(user.name))
            else:
                print("{0}的签名验证失败！".format(user.name))

message = 'test123'
user1 = User('user1')
user2 = User('user2')
user3 = User('user3')
print("{0} 对消息 {1} 进行签名".format(user1.name,message))
miwen = user1.sign(message)
print("传递给user2进行验证(结果应为成功，因为user1签了字): ")
user2.check(message,user1,miwen)
print("user3验证user2的签名(结果应该失败，因为user2未签字): ")
user3.check(message,user2,miwen)
