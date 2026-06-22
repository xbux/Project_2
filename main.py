import aiohttp, asyncio, tasksio, nest_asyncio



class MICROSOFT:
    
    def __init__(self):
        self._accounts = [_line.strip()
                          for _line in open('accounts.txt', 
                                            encoding = 'utf-8').readlines()
                          if _line not in ['\r', '\n']]
        
        self._success = 0
        
        
    async def get_response_from_url(self, _session):
        _url_encode = ['client_id=000000004415494b',
                       'redirect_uri=ms-xal-000000004415494b://auth', 
                       'response_type=token', 
                       'scope=service::user.auth.xboxlive.com::MBI_SSL']
        
        _join = '&'.join(_url_encode)
        
        _url = 'https://login.live.com:443/oauth20_authorize.srf?' + _join
        
        async with _session.get(_url) as response:
            _text = await response.text()
            
            _ppft = _text.split(r'name=\"PPFT\" id=\"i0327\" value=\"')[1].split('\"')[0]
            _post = _text.split('"urlPost":"')[1].split('","')[0]
            return _ppft, _post
        
    async def login_into_account(self, _account):
        _aiohttp_header = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
                           'Upgrade-Insecure-Requests': '1', 
                           'Accept-Encoding': 'gzip, deflate, br, zstd',
                           'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                           'Accept-Language': 'en-US,en;q=0.9',
                           'Connection': 'Keep-Alive'}

        _aiohttp_connector = aiohttp.TCPConnector(ssl = False, limit = 0)
        _aiohttp_version = aiohttp.HttpVersion10
        _aiohttp_cookie = aiohttp.CookieJar(quote_cookie = True)

        async with aiohttp.ClientSession(
                                         trust_env  = True, 
                                         connector  = _aiohttp_connector,
                                         headers    = _aiohttp_header,
                                         version    = _aiohttp_version,
                                         cookie_jar = _aiohttp_cookie) as _session:
            
            _ppft, _post = await self.get_response_from_url(_session)
            _account_format = _account.split(':')
            _payload  = {'PPSX'         : 'Passport'                 ,
                         'SI'           : 'Sign in'                  ,
                         'LoginOptions' : '1'                        ,
                         'i18'          : '__Login_Host|1'           ,
                         'login'        :  f'{_account_format[0]}'   ,
                         'loginfmt'     :  f'{_account_format[0]}'   ,
                         'passwd'       :  f'{_account_format[1]}'   ,      
                         'PPFT'         : f'{_ppft}'                 }
            
            _current_tries = 0
            while _current_tries < 30:       
                async with _session.post(_post, data = _payload, allow_redirects = False) as response:
                    _current_tries += 1
                    _headers = response.headers
                    if 'Location' not in _headers:
                        continue
                    
                    _location = _headers['Location']
                    _access = _location.split('access_token=')[1].split('&token_type=')[0]
                    await self.exchange_access_for_user(_session, _access, _account_format[0])
                    break
        
            
    async def exchange_access_for_user(self, _session, _access, _email):
        _payload = {
            'RelyingParty':'http://auth.xboxlive.com',
            'TokenType':'JWT',
            'Properties':{
                'AuthMethod':'RPS',
                'RpsTicket':f't={_access}',
                'SiteName':'user.auth.xboxlive.com'}}
        async with _session.post('https://20.201.200.93:443/user/authenticate',
                                 json = _payload) as response:
            
            _json = await response.json()
            _user_token = _json['Token']
            with open('user_tokens.txt', 'a', encoding = 'utf-8') as file:
                file.write(f'{_user_token}\n')
            
            self._success += 1
            print(f' ! {_email} success - ({self._success}/{len(self._accounts)})')
        
    async def start_all_processes(self):
        for _second in ['3', '2', '1']:
            print(f' + Starting in {_second} seconds...', end = '\r')
            await asyncio.sleep(1)
            
        async with tasksio.TaskPool(20) as _taskpool:
            for _account in self._accounts:
                await _taskpool.put(self.login_into_account(_account))
                
        input(f'\n + Successfully get: {self._success} authorizations')                                
        

microsoft = MICROSOFT()
nest_asyncio.apply()
print(' + Microsoft User_Authorization Extractor \n')

asyncio.run(microsoft.start_all_processes())