NEXUS_LOGIN_URL = 'https://www.nexusmods.com/oblivion/sessions/?Login'

class NexusDownloader:
    def __init__(self, username, password):
        self.sess = requests.session()
        self.username = username
        self.password = password
        self.redirect_re = re.compile(r'(?ms).*?window\.location\.href = "(http://filedelivery\.nexusmods\.com[^"]*?)".*')
        self.logged_in = False
    
    def login(self):
        resp = self.sess.post(NEXUS_LOGIN_URL, data={'username': self.username, 'password': self.password})
        resp.raise_for_status()
        self.logged_in = True
        logger.info('successfully logged into Nexus Mods')
    
    def download(self, url, dest_path, autoname=False):
        if not self.logged_in:
            logger.info('not logged in, logging in')
            self.login()
        page_text = self.sess.get(url).text
        new_url = self.redirect_re.match(page_text).group(1)
        dl_file_pbar(new_url, dest_path, sess=self.sess, autoname=autoname)