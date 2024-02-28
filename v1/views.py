from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
import firebase_admin, json, secrets, requests, bcrypt, razorpay
from firebase_admin import credentials, firestore
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


firebaseConfig = {
    "type": "service_account",
    "project_id": "l2lacademy",
    "private_key_id": "c1f3cf29186efe8d0cd7ec2212bba1149a1bfcfb",
    "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC4iFX1Fdl9m+4W\n+nEPli/gHmLSmIBAWJsY3E6gxykQK0gf0qKx+zRzarCDbL6C3leE4ZBsZY1uYZ6j\nOciB/BT23EoXVZkqDbf3vLMZ+vTCbtOHhnyr8/p7EH6JJg43NV92A20C4IBFobpy\nYFRhItFXm7SB01Zvy/1QE12u7FE/WfopH8c0XsDBs+LNpUm2Ktbb4s652l91u3G4\nEvBaaKfIODvvGlINaFHLcVQo7iY95XzxXE1EFtltw8s6Lkzs2VwnsH5Jm8OCfcyR\npcG73RCUevVDAfpVcdusLKE1Y9xV2kY0G1cSUMsoCOWg0p/v5pKlWIyq9kQ/bc1r\nwKi+a1D/AgMBAAECggEAEzp5ooE1WYZfB9vu3g3rTTI9X+5uJsZU2wFR3CUEnV+1\nM0OymlMvwvsSC4/QRji+6+TJNNJcK21Wp3GE+C55TMPloIrV2/D0A4eRLhrdWElO\nF2gnI4/XwO0WElp5zrzsBpMSz+Lu2tKgZ/yrrjd/kt5xr7mC30FlUuvBrlGHoc8j\n6iGGcEDjjpEPfD9Dlpw0s0Soo00fDbAUGe/V20BoQbBuCTD3sSbySykDZEWewWx2\nGfp49O/+ahk4Mo5G8cktWrAB9s738nPj9Ubke4Iuwndst5U9Afx+RE1BVv/nyQHB\nZCVHM0nGo7dr+UfcoiDmrdsmvmu0j4WvUxvSO4XzEQKBgQDuSYM4soM3lxG63uOu\nGKOy3TCl0eOUY1PciKkuyPCw+eax8X0wCh/hJfcROjZs6GHObb/sduCtk4kxUFGg\nDlJMTlaDWn8xne40hinllddWCfocvs+/fqVmS4/KP/fXgM8nczJEdBA1vTNqvbqp\ntT1nb4x3hXZLxXzwvQo2id14eQKBgQDGP+ZPYxsVbTABa/kOvkMNX1MO7dIxROUZ\nBu3n/UWZiMEJRh0n7mqJYkn+qFqROJqHeTSUGy/SoSZPP1o9FIEr0c2Q9vLuSG7Q\nkbsluIjsfLN77DmOII3+0CerDTeVFhA9rydmpKnZs1TytRDEe+ft9xZlr1xlXjqH\ntO4aD1wnNwKBgQCp05LGMdP7JpvoRzqVtdHVhHdLdw9vjmsSXgPV6DhCqZiVcbr7\nJfwahuhTSt3HOMecS/PhH8h5bRD2KHxESnC1GY/nBfRo9Fn07Tmm+ugB1hJ/si52\nGFjhUzEjv/tvh8ocH6nPx7hV1IZ0qMwEb7tXoNTHykLJNfMZ0GEbBZ7mYQKBgQCR\nsK/uM2TZ8C3RPaoAPa5FC4KcfAV2E61RIRiA3k3hsPA7gn02tS0x3TuHm+1Cv5hA\nasBK/1e7sJXYszP7oy/yJfKtz+1jU3OsbwxbgiuNr26vaUA6xI3Vbt9YAxSPyXES\nA8Au3F++Dt4kpw+1dWFSLb0V6TM7g238AOjh2dvdLQKBgDO/os9oCYt0Ow/Sj5E0\niqHmOawzEtyLAeWKar77qCWx4esQCtin4REoDuBXhTuTCystxAUOc80lPvO6H0Cp\npn8iLD+YpI57ocC7A8zbf1FwJHca/jxjzb7L5nXtsm1y6gpzR+OWvf15sACu2XLY\n1hSXtdGwuGaR82DVuh8nl6h/\n-----END PRIVATE KEY-----\n",
    "client_email": "firebase-adminsdk-m1rrr@l2lacademy.iam.gserviceaccount.com",
    "client_id": "109470056256571555377",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-m1rrr%40l2lacademy.iam.gserviceaccount.com",
    "universe_domain": "googleapis.com"
}
# Initialize Firebase with the dictionary configuration
app = firebase_admin.initialize_app(credentials.Certificate(firebaseConfig))
db = firestore.client()
otpRef = db.collection('OTPs')
userRef = db.collection('users')
# Create your views here.

def sendwhatsappOTP(name, mobileNo,otp):
    url = 'https://backend.aisensy.com/campaign/t1/api/v2'
    headers = {
        'Content-Type': 'application/json',
    }
    data = {
        "apiKey": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY1NjE4NjE0YTk3NTIzN2ZjMmEzNmUwYyIsIm5hbWUiOiJMZWFybiAyIExlYXJuIEFjYWRlbXkiLCJhcHBOYW1lIjoiQWlTZW5zeSIsImNsaWVudElkIjoiNjU2MTg2MTNhOTc1MjM3ZmMyYTM2ZTA3IiwiYWN0aXZlUGxhbiI6IkJBU0lDX01PTlRITFkiLCJpYXQiOjE3MDA4OTAxMzJ9.K3wRKQTXxSJAdn4mztjEtwpD9v8OtQyMTBR0_xMqG80",
        "campaignName": "Auth_Otp",
        "destination": "91"+mobileNo,
        "userName": name,
        "templateParams": [
            name,
            otp
        ],
        "tags": [
            "Verified",
            "NEET Mock"
        ]
    }
    response = requests.post(url, json=data, headers=headers)
    return response
    
def otp_generate():
    otp = secrets.randbelow(10**6)
    otp_str = f'{otp:06}'
    data={'otp':hash_password(otp_str)}
    update_time, otp_ref = otpRef.add(data)
    return {'otp':otp_str, 'refID':otp_ref.id}

def hash_password(password):
    # Hash the password using bcrypt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    # Convert the hashed password bytes to a string
    return hashed_password.decode('utf-8')

def verify_password(plain_text_password, hashed_password):
    # Verify the provided password against the stored hash
    return bcrypt.checkpw(plain_text_password.encode('utf-8'), hashed_password.encode('utf-8'))


def sendEmailOTP(reciever_email,otp):
    htmlTemp = f"""<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>One Time Password</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 0;
            text-align: center;
        }}
        .container {{
            max-width: 600px;
            margin: 50px auto;
            background-color: #ffffff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            text-align: center; /* Center the content within the container */
        }}

        header {{
            border-radius: 8px 8px 0 0;
            overflow: hidden;
            display: flex;
            flex-direction: column;
            align-items: center;
        }}

        .logo {{
            background-color: #ffffff;
            padding: 10px;
            box-sizing: border-box;
            width: 50%; /* Adjust the width accordingly */
        }}

        .company-name  {{
            background-color: #007bff;
            color: #ffffff;
            padding: 10px;
            box-sizing: border-box;
            width: 100%;
        }}

        h2 {{
            margin: 0;
            display: inline-block;
        }}

        img {{
            max-width: 100%;
            height: auto;
        }}

        h1 {{
            color: #333333;
        }}

        p {{
            color: #666666;
        }}

        .otp-code {{
            font-size: 32px;
            font-weight: bold;
            color: #ffffff;
            background-color: #007bff;
            padding: 15px 30px;
            border-radius: 8px;
            margin-top: 20px;
            margin-bottom: 20px;
            display: inline-block;
        }}

        .footer {{
            margin-top: 20px;
            color: #999999;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">
                <img src="https://thel2lacademy.com/wp-content/uploads/2024/02/l2l.png" alt="Company Logo">
            </div>
            <div class="company-name">
                <h2>Learn 2 Learn Academy</h2>
            </div>
        </header>
        <h1>One Time Password (OTP)</h1>
        <p>Your One Time Password (OTP) is:</p>
        <div class="otp-code">{otp}</div>
        <p>This OTP is valid for a short period. Do not share it with anyone.</p>
        <p>If you did not request this OTP, please ignore this email.</p>
        <p class="footer">Thank you,<br>Learn 2 Learn Academy</p>
    </div></body></html>"""
    sender_name = "L2L Academy"
    sender_email = "no-reply@thel2lacademy.com"
    subject = "OTP Confirmation!"
    message = MIMEMultipart()
    message["From"] = f"{sender_name} <{sender_email}>"
    message["To"] = reciever_email
    message["Subject"] = subject
    html_body = MIMEText(htmlTemp, "html")
    message.attach(html_body)
    smtp_server = "smtp.hostinger.com"
    smtp_port = 465
    smtp_password = "Ganeshsir@l2l"
    smtp_conn = smtplib.SMTP_SSL(smtp_server, smtp_port)
    smtp_conn.login(sender_email, smtp_password)
    smtp_conn.sendmail(sender_email, reciever_email, message.as_string())
    smtp_conn.quit()



@csrf_exempt
def mobile_otp(request):
    if request.method == 'POST':
        user_data = json.loads(request.body.decode('utf-8'))

        # Access individual fields
        uid = user_data.get('uid', '')
        

        user_mob = userRef.document(uid).get()
        if user_mob.exists:
            data = user_mob.to_dict()
            mobileNo = data['mobileNo']
            mobile_otp = otp_generate()
            # email_otp = otp_generate()
            name = data['name']
            update_time, user_ref = userRef.add(data)
            sendwhatsappOTP(name, mobileNo, mobile_otp['otp'])
            re = {
                'status':200,
                'refID':mobile_otp['refID']
                }
            return JsonResponse(re)

    return JsonResponse({'error': 'Invalid request method'})

@csrf_exempt
def verifyOTP(request):
    if request.method == 'POST':
        data = json.loads(request.body.decode('utf-8'))
        otp = data.get('otp', '')
        refID = data.get('refID')
        doc_data = otpRef.document(refID).get()
        if doc_data.exists:
            if verify_password(otp, doc_data.to_dict()['otp']):
                otpRef.document(refID).delete()
                return JsonResponse({'validation':True, 'code': '01'})

        return JsonResponse({'validation':False, 'code': '00'})
    
    return HttpResponse("Invalid method", status=405)

@csrf_exempt
def email_otp(request):
    if request.method == 'POST':
        user_data = json.loads(request.body.decode('utf-8'))

        # Access individual fields
        email = user_data.get('email', '')
    
        
            
        email_otp = otp_generate()
            # email_otp = otp_generate()
            # update_time, user_ref = userRef.add(data)
            # sendwhatsappOTP(name, mobileNo, mobile_otp['otp'])
        re = {
                # 'uid':user_ref.id,
                'status':200,
                'refID':email_otp['refID']
                }
        return JsonResponse(re)

    return JsonResponse({'error': 'Invalid request method'})