import requests
import os
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Key_Auto_Get(object):
    def __init__(self):
        self.api_base_url = os.getenv("API_URL") if os.getenv("API_URL") else "https://127.0.0.1:3443"
        print(self.api_base_url)
        self.login_url = self.api_base_url + "/api/v1/me/login"
        self.info_url = self.api_base_url + "/api/v1/me"
        self.graphql_url = self.api_base_url + "/graphql/"
        self.username = "admin@admin.com"
        self.password = "3b612c75a7b5048a435fb6ec81e52ff92d6d795a8b5a9c17070f6a63c97a53b2"
        self.remeberme = True
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
            "X-Auth":"",
            "Cookie":""
        }

        self._api_key = None

        self.sess = requests.Session()

        # 获取key流程
        try:
            self.login()
            self.update_me_profile()
            self.get_me_info()
            if self.get_key() is None:
                self.generate_key()
                self.get_key()
            else:
                pass
        except Exception as e:
            print(e)

    def login(self):
        login_data = {
            "email": self.username,
            "password": self.password,
            "remember_me": self.remeberme
        }
        res = self.sess.post(self.login_url, json=login_data, verify=False)
        # print(res.status_code)
        # print(res.headers)
        self.headers["X-Auth"] = res.headers["X-Auth"]
        self.headers["Cookie"] = res.headers["Set-Cookie"]

    def get_me_info(self):
        res = self.sess.get(self.info_url, verify=False,headers=self.headers)
        # print(res.text)
        return res

    def update_me_profile(self):
        update_profile_data = {"operationName":"updateProfile","variables":{"profile":{"firstName":"Administrator","lastName":"w1nd","language":"CN","timeZone":None,"notifications":{"scans":True,"targets":True,"reports":True,"attachments":False,"links":False,"mute":False,"workers":True}}},"query":"mutation updateProfile($profile: UserProfileUpdateInput!) {\n  updateProfile(profile: $profile)\n}"}
        res = self.sess.post(self.graphql_url, json=update_profile_data,verify=False,headers=self.headers)
        # print(res.status_code)
        # print(res.text)

    def generate_key(self):
        generate_key_data = {"operationName":"generateApiKey","variables":{},"query":"mutation generateApiKey {\n  generateApiKey\n}"}
        res = self.sess.post(self.graphql_url, json=generate_key_data,verify=False,headers=self.headers)

    def get_key(self):
        get_key_data = {"operationName":"apiKey","variables":{},"query":"query apiKey {\n  apiKey\n}"}
        res = self.sess.post(self.graphql_url, json=get_key_data,verify=False,headers=self.headers)
        # print(res.json())
        self._api_key = res.json()["data"]["apiKey"]
        return self._api_key



# Key_Auto_Get()
