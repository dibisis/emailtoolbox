import base64
import json
import random
import re
import socket

import dns.resolver
import requests
from flask import Flask, send_from_directory
from flask import escape
from flask import render_template, redirect
from flask import request
from flask import session
from json2html import *
from oauth2client.contrib.flask_util import UserOAuth2

app = Flask(__name__)

app.config['SECRET_KEY'] = 'somesecretkeyishere'

authUser = ["dibisis@gmail.com"]

# https://oauth2client.readthedocs.io/en/latest/source/oauth2client.contrib.flask_util.html
app.config['GOOGLE_OAUTH2_CLIENT_ID'] = 'GOOGLE_OAUTH2_CLIENT_ID_you_can_get_from_gcloud_console'

app.config['GOOGLE_OAUTH2_CLIENT_SECRET'] = 'GOOGLE_OAUTH2_CLIENT_SECRET_you_can_get_from_gcloud_console'

app.config['HOME_DIR'] = './'
oauth2 = UserOAuth2(app)


# logging


@app.route('/')
def main_redirect():
    app.logger.info('info message')

    authresult = {'isAuthUser': isAuth(oauth2.email), 'email': oauth2.email,
                  'has_credentials': oauth2.has_credentials()}

    return render_template("index.html", authresult=authresult)


@app.route('/login')
@oauth2.required
def login():
    return redirect('/')


@app.route('/logout')
# @oauth2.required
def logout():
    session.clear()
    return redirect('/')


@app.route('/robots.txt')
def robot_to_root():
    return send_from_directory(app.static_folder, request.path[1:])


@app.route('/decode5', methods=['GET'])
# http://domain.here/decode/test.com
def decode5():
    # siteurl = request.args.get('siteurl', type=str)
    siteurl = request.query_string.decode('utf-8')

    # decode logic is censored
    result = siteurl

    return result


@app.route('/decode6', methods=['GET'])
# http://domain.here/decode6/test.com
def decode6():
    if not isAuth(oauth2.email):
        return "@domain.here계정로그인이 필요합니다. https://domain.here 로 로그인하세요"
    siteurl = request.args.get('siteurl', type=str)

    if siteurl == "blank":
        return "blank"
    checkresult = "  URL 복호화 대상: " + siteurl + "<br/><hr/>"

    # parsing url
    slipturl = siteurl.split("/")
    print(slipturl)
    for queryword in slipturl:
        if len(queryword) < 15:
            continue
        try:
            result = devglan_aes_api(queryword)
        except:
            result = "형식오류"
        checkresult = checkresult + queryword + " : </br> => <br/><b>" + result + "</b><br><hr/>"

    return checkresult


@app.route('/white/<siteurl>', methods=['GET'])
# http://domain.here/white/test.com
def check_white(siteurl):
    if siteurl == "blank":
        return "blank"

    print("url:" + siteurl)
    checkresult = kisahackcheck(siteurl)

    return checkresult


@app.route('/mxhistory/<domain>')
def mx_history(domain):
    if domain == "blank":
        return "blank"
    if isAuth(oauth2.email) == False:
        return "yourorg.com 계정로그인이 필요합니다. https://domain.here 로 로그인하세요"
    # apikey list : keychange

    apikeylist = ["apikeyhere_1", "apikeyhere_2",
                  "apikeyhere_3"]
    apikey = random.choice(apikeylist)

    domain = domain.strip()
    try:
        responsetext = mxhistory(domain, apikey)

        responsetext = json.loads(responsetext)
        returntable = json2html.convert(json=responsetext['records'])
    except:
        return "조회불가"
    print(apikey)
    return returntable


@app.route('/verify/<emailaddress>')
def check_email(emailaddress):
    if emailaddress == "blank":
        return "blank"
    emailaddress = emailaddress.strip()
    if emailsyntaxcheck(emailaddress):
        emailaccount, emaildomain = emailaddress.split("@")
        checkresult = "이메일 형식 정상"
        resultraw = connectsmtpraw(emailaccount, emaildomain)
        checkresult = resultraw
    else:
        checkresult = "이메일 형식 오류"

    print(checkresult)
    checkresult = escape(checkresult)
    checkresult = "<br />".join(checkresult.split("\n"))
    return checkresult


@app.route('/verifyall/<emailaddress>')
def check_email_all(emailaddress):
    if emailaddress == "blank":
        return "blank"
    if isAuth(oauth2.email) == False:
        return "yourorg.com 계정로그인이 필요합니다. https://domain.here 로 로그인하세요"
    emailaddress = emailaddress.strip()
    if emailsyntaxcheck(emailaddress):
        emailaccount, emaildomain = emailaddress.split("@")
        checkresult = "이메일 형식 정상"
        resultraw = connectsmtprawall(emailaccount, emaildomain)
        checkresult = resultraw
    else:
        checkresult = "이메일 형식 오류 <br />"

    print(checkresult)
    checkresult = escape(checkresult)
    checkresult = "<br />".join(checkresult.split("\n"))
    return checkresult


@app.route('/master/<emailaddress>')
def check_all_in_one(emailaddress):
    if emailaddress == "blank":
        return "blank"
    if isAuth(oauth2.email) == False:
        return "yourorg.com 계정로그인이 필요합니다. https://domain.here 로 로그인하세요"

    checkresult = ""
    emailaddress = emailaddress.strip()
    if "@" in emailaddress:
        print("email address")
        if (emailsyntaxcheck(emailaddress)):
            emailaccount, emaildomain = emailaddress.split("@")
            checkresult = "이메일 형식 정상"
            resultraw = connectsmtprawall(emailaccount, emaildomain)
            checkresult = resultraw
        else:
            checkresult = "이메일 형식 오류 \n"

        checkresult = escape(checkresult)
        checkresult = "<br />".join(checkresult.split("\n"))

        apikeylist = ["apikeyhere_1", "apikeyhere_2",
                      "apikeyhere_3"]
        apikey = random.choice(apikeylist)

        try:
            print(emaildomain)
            responsetext = mxhistory(emaildomain, apikey)

            responsetext = json.loads(responsetext)
            returntable = json2html.convert(json=responsetext['records'])

            print(returntable)
            checkresult = checkresult + returntable
        except:
            checkresult = checkresult + "도메인 조회불가"
        print(apikey)
    else:
        print("domain")
        domain = emailaddress
        apikeylist = ["apikeyhere_1", "apikeyhere_2",
                      "apikeyhere_3"]
        apikey = random.choice(apikeylist)

        try:
            responsetext = mxhistory(domain, apikey)

            responsetext = json.loads(responsetext)
            returntable = json2html.convert(json=responsetext['records'])
            checkresult = returntable
        except:
            checkresult = "도메인 조회불가"

    return checkresult


def decode5url(url):
    print(url)
    # GET /response/response.do?method=MO29304&SND=MjIxNjIy&MMD=ODkzNw==&SDD=MQ== HTTP/1.1

    # below stinrg Tm9uZQ== means "None"
    sendid = "Tm9uZQ=="
    massmailid = "Tm9uZQ=="
    scheduleid = "Tm9uZQ=="

    # parse open url
    # 1.if url contains response do use SND=,MMD=,SSD=
    if "response" in url:
        print("response")
        sendid = find_between(url, "SND=", "&MMD=")
        massmailid = find_between(url, "&MMD=", "&SDD=")
        scheduleid = find_between(url, "&SDD=", "==")

    # 2.if url contains open/EQ/ do use SND/EQ,MMD/EQ,SSD/EQ
    # GET /open/EQ/MO29304/AP/SND/EQ/NDI0MzQy/AP/MMD/EQ/ODk1MA==/AP/SDD/EQ/MQ==.gif HTTP/1.1
    # GET%20%2Fopen%2FEQ%2FMO29304%2FAP%2FSND%2FEQ%2FNDI0MzQy%2FAP%2FMMD%2FEQ%2FODk1MA%3D%3D%2FAP%2FSDD%2FEQ%2FMQ%3D%3D.gif%20HTTP%2F1.1
    if "open/EQ/" in url:
        print("open/EQ/")

        sendid = find_between(url, "/SND/EQ/", "/AP/MMD/")
        massmailid = find_between(url, "/MMD/EQ/", "/AP/SDD")
        scheduleid = find_between(url, "/SDD/EQ/", "==")

    # set dict and return
    # notice : need padding(=======)

    decodedsendid = base64.b64decode(sendid + "=============").decode('utf-8')
    decodedmassmailid = base64.b64decode(
        massmailid + "=============").decode('utf-8')
    decodedscheduleid = base64.b64decode(
        scheduleid + "=============").decode('utf-8')
    return {'sendid': decodedsendid, 'massmailid': decodedmassmailid, 'scheduleid': decodedscheduleid}


def devglan_aes_api(queryword):
    apiurl = "https://www.devglan.com/online-tools/aes-decryption"
    payload = "{\"textToDecrypt\":\"" + queryword + "\",\"secretKey\":\"somesecreKeyishere\",\"mode\":\"ECB\"," \
                                                    "\"keySize\":\"128\",\"dataFormat\":\"Hex\"} "
    headers = {
        'sec-fetch-mode': 'cors',
        'dnt': '1',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'en-US,en;q=0.9,ko;q=0.8,la;q=0.7',
        'cookie': '_ga=GA1.2.1974992906.1566792978; _gid=GA1.2.1071800042.1566792978; '
                  'JSESSIONID=DBA6A4FA4578BF720E7D033F47BD3C22',
        'pragma': 'no-cache',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                      'Chrome/76.0.3809.100 Safari/537.36',
        'content-type': 'application/json;charset=UTF-8',
        'accept': 'application/json, text/plain, */*',
        'cache-control': 'no-cache',
        'authority': 'www.devglan.com',
        'referer': 'https://www.devglan.com/online-tools/aes-encryption-decryption',
        'sec-fetch-site': 'same-origin',
        'origin': 'https://www.devglan.com'}
    response = requests.request("POST", apiurl, headers=headers, data=payload)

    responsetext = json.loads(response.text)
    result = responsetext['output']

    result = base64.b64decode(result).decode('utf-8')
    return result


def find_between(s, first, last):
    try:
        start = s.index(first) + len(first)
        end = s.index(last, start)
        return s[start:end]
    except ValueError:
        return ""


def kisahackcheck(url):
    # success stirng
    success_string = "alert('이미 등록되어 있는 도메인입니다. 화이트 IP 조회 페이지로 이동합니다.');"

    request_headers = {
        'User-Agent': ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 '
                       '(KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36')
    }
    get_params = {'userType': '1', 'mailDomain': url}
    response = requests.post(
        'https://spam.kisa.or.kr/white/sub41.do',
        headers=request_headers,
        params=get_params)

    if success_string in response.text:
        result = "<html><body> %s<br> 이미 등록되어 있는 도메인입니다</body></html>" % url
    else:
        result = '<html><body> %s<br><p><span style=\'color: #ff0000;\'>미등록 도메인 입니다.</span></p><p><a ' \
                 'href=\'http://tmurl.kr/white\'>http://tmurl.kr/white</a>를&nbsp;참고하셔서 등록하시면 됩니다.</p></body></html>' \
                 % url

    return result


def emailsyntaxcheck(emailaddress):
    addressToVerify = emailaddress
    # match = re.match("'^[+_a-z0-9-]+(\.[_a-z0-9-+]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$", addressToVerify)
    rfc_regex = (r"(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|" r'"(?:[' "\n"
                 r'    \x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[' "\n"
                 r"    a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(" "\n"
                 r"    5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[" "\n"
                 r"    \x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\]) ")

    match = re.match(rfc_regex, addressToVerify)

    print(rfc_regex)
    if match is None:
        print('Bad Syntax')
        return False
    return True


def connectsmtpraw(emailaccount, emaildomain):
    # mx레코드 하나에 접속 시도

    rawresult = ""
    helodomain = "test.com"
    mailfromaddress = "return@test.com"

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.settimeout(10)
    # client_socket.connect(("192.168.0.119", 25))

    tempmx = getMXrecord(emaildomain)
    if (tempmx is None):
        rawresult = " 없는 도메인입니다."
        client_socket.close()
        return rawresult

    mxhighpriority = str(tempmx[0].exchange)

    mxrecordall = str(tempmx.rrset)

    rawresult = rawresult + "MX record 조회 결과 : \n" + mxrecordall + "\n"

    rawresult = rawresult + "=================================\n"

    rawresult = rawresult + "연결시도 : " + mxhighpriority + "\n"

    rawresult = rawresult + "=================================\n"

    try:
        client_socket.connect((mxhighpriority, 25))
    except Exception as e:
        rawresult = rawresult + "연결실패 (" + str(e) + ") : " + mxhighpriority + "\n"
        client_socket.close()
        return rawresult
    # noinspection DuplicatedCode
    try:
        data = client_socket.recv(512).decode()

        rawresult = rawresult + data

        data = "HELO " + helodomain + "\r\n"

        rawresult = rawresult + data
        print("=> ", data)

        sendbyte = client_socket.send(data.encode())
        print(sendbyte)

        data = client_socket.recv(512).decode()
        rawresult = rawresult + data
        # print("<= ", data)

        data = "MAIL FROM:<" + mailfromaddress + ">\r\n"
        rawresult = rawresult + data
        # print("=> ", data)
        client_socket.send(data.encode())

        data = client_socket.recv(512).decode()
        rawresult = rawresult + data
        # print("<= ", data)

        data = "RCPT TO:<" + emailaccount + "@" + emaildomain + ">\r\n"
        # print("=> ", data)
        rawresult = rawresult + data
        client_socket.send(data.encode())

        data = client_socket.recv(512).decode()
        # print("<= ", data)
        rawresult = rawresult + data

        data = "QUIT\r\n"
        # print("=> ", data)
        rawresult = rawresult + data
        client_socket.send(data.encode())

        data = client_socket.recv(512).decode()
        # print("<= ", data)
        rawresult = rawresult + data
    except Exception as e:
        return rawresult + "\n" + str(e)
        client_socket.close()

    client_socket.close()

    return rawresult


def connectsmtprawall(emailaccount, emaildomain):
    # mx레코드 하나에 접속 시도

    rawresult = ""
    helodomain = "test.com"
    mailfromaddress = "return@test.com"

    # client_socket.connect(("192.168.0.119", 25))

    tempmx = getMXrecord(emaildomain)
    # (str(getMXrecord(emaildomain).exchange)
    if (tempmx is None):
        rawresult = " 없는 도메인입니다."
        return rawresult

    mxrecordall = str(tempmx.rrset)

    rawresult = rawresult + "MX record 조회 결과 : \n" + mxrecordall + "\n"

    for item in tempmx:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(10)
        mxhighpriority = str(item.exchange)

        rawresult = rawresult + "=================================\n"

        rawresult = rawresult + "연결시도 : " + mxhighpriority + "\n"

        rawresult = rawresult + "=================================\n"

        try:
            client_socket.connect((mxhighpriority, 25))
        except Exception as e:
            rawresult = rawresult + "연결실패 (" + str(e) + ") : " + mxhighpriority + "\n"
            client_socket.close()
            return rawresult
        try:
            data = client_socket.recv(512).decode()

            rawresult = rawresult + data

            data = "HELO " + helodomain + "\r\n"

            rawresult = rawresult + data
            # print("=> ", data)
            client_socket.send(data.encode())

            data = client_socket.recv(512).decode()
            rawresult = rawresult + data
            # print("<= ", data)

            data = "MAIL FROM:<" + mailfromaddress + ">\r\n"
            rawresult = rawresult + data
            # print("=> ", data)
            client_socket.send(data.encode())

            data = client_socket.recv(512).decode()
            rawresult = rawresult + data
            # print("<= ", data)

            data = "RCPT TO:<" + emailaccount + "@" + emaildomain + ">\r\n"
            # print("=> ", data)
            rawresult = rawresult + data
            client_socket.send(data.encode())

            data = client_socket.recv(512).decode()
            # print("<= ", data)
            rawresult = rawresult + data

            data = "QUIT\r\n"
            # print("=> ", data)
            rawresult = rawresult + data
            client_socket.send(data.encode())

            data = client_socket.recv(512).decode()
            # print("<= ", data)
            rawresult = rawresult + data
        except Exception as e:
            return rawresult + "\n" + str(e)
            client_socket.close()
        client_socket.close()

    return rawresult


def getMXrecord(domain):
    try:
        # noinspection PyDeprecation
        records = dns.resolver.query(domain, 'MX')
    except Exception as ex:
        print('에러가 발생 했습니다', ex)
        records = None

    return records


def mxhistory(domain, apikey):
    url = "https://api.securitytrails.com/v1/history/" + domain + "/dns/mx"

    querystring = {"apikey": apikey}

    response = requests.request("GET", url, params=querystring)

    return response.text


def isAuth(email):
    if email is None:
        return False
    elif email in authUser:
        return True
    elif email.endswith("yourorg.com"):
        return True
    else:
        return False


if __name__ == '__main__':
    app.run()
