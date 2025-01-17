# ADESA - Active Directory Essential Security Auditor

A web application for auditing Microsoft Active Directory instances on the Essential 8, outlines by the ACSC (Australian Cyber Security Centre).

Code has been shared as part of a undergraduate thesis. For real world use, this would be close-sourced and deployed to the cloud where clients could connect directly to utilise the service.

## Installation and usage

Clone or download the source code, navigate to the root folder and create a python virtual environment with Python version >= 3.7.

```bash
python3 -m venv path/to/virtualenv
```

Start the virtual environment and install required packages. Use the package manager [pip](https://pip.pypa.io/en/stable/).
```bash
source path/to/virtualenv/bin/activate
pip install -r requirements.txt
```

To start the server, enter the following command.
```bash
python3 /path/to/ADESA/manage.py runserver
```

To enable email notification functions, at the bottom of the settings file update the user and password fields to your own.
```python
# EMAIL SETTINGS

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_USE_TLS = True
EMAIL_PORT = 587
EMAIL_HOST_USER = 'YOUR EMAIL'
EMAIL_HOST_PASSWORD = 'YOUR PASSWORD'
```

In production be sure to hide the secret key from the settings file!

## Notes

The application relies on ssh to audit the Windows Servers that it connects to. Ensure that your Windows Server/Active Directory instance allows ssh access.

This application was developed with python v3.7 and Windows Server 2012. 
## License
[MIT](https://github.com/cmcadam/ADESA/blob/master/LICENSE)