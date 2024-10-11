import requests
import urllib3
from urllib.parse import urlparse, urlunparse
import warnings


html_report = []
supported_versions = []
warnings.simplefilter("ignore", category=urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

def banner():
    print("-" * 86)
    print(" " * 26 + "Low Hanging Fruit Security Scanner")
    print(" " * 40 + "v1.0")
    print(" " * 31 + "Another tool by TheMayor")
    print("-" * 86)

    banner_html = f"""
    <html>
    <!--Generated with the Low Hanging Fruit Security Scanner by TheMayor-->
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; }}
            .banner {{ text-align: center; padding: 10px; background-color: #f8f9fa; }}
            .section {{ margin: 20px; text-align: center; padding: 10px; border: 1px solid #dee2e6; border-radius: 5px; background-color: #f8f9fa;}}
            .prep-div {{text-align: center; padding: 10px; background-color: #f8f9fa; }}
            .section-title {{ font-size: 18px; font-weight: bold; }}
            .section-medium {{ font-size: 16px; font-weight: bold; }}
            .small-text {{ font-size: 12px; text-align: left; }}
            .secure {{ color: darkgreen; font-weight: bold; font-size: 14px; }}
            .missing-header {{ color: red; font-size: 14px; text-align: center; max-width: 1200px; margin: 0 auto; white-space: normal; }}
            .vulnerable {{ color: red; font-size: 14px; }}
            .a-score {{ color: darkgreen; font-weight: bold; }}
            .b-score {{ color: green; font-weight: bold; }}
            .c-score {{ color: goldenrod; font-weight: bold; }}
            .d-score {{ color: orange; font-weight: bold; }}
            .f-score {{ color: maroon; font-weight: bold; }}
        </style>
    </head>
    <body>
    <div class="banner">
        <h1>Low Hanging Fruit Security Scanner</h1>
        <h2>v1.0</h2>
        <h3>Another tool by TheMayor</h3></div>
    """
    html_report.append(banner_html)
def secondary_banner(target):
    secondary_banner_html = f"""
        <div class="prep-div">
        <h3>Report prepared for:</h3>
        <h4>{target}</h4>
        </div></div>
    """
    html_report.append(secondary_banner_html)
def security_header_check(target):


    grade_counter = 0
    global hsts, grade
    section_html = f"""
    <div class="section">
        <div class="section-title">Security Header Score Card
    </div>"""
    try:
        response = requests.get(target, verify=False)
        print("\n" + "-" * 30 + "Security Header Score Card" + "-" * 30)
        # Get the headers from the response
        headers = response.headers

        # List of common security headers to check
        security_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Referrer-Policy',
            'Permissions-Policy'
        ]

        # Check and print the presence and value of each security header
        missing_headers = [header for header in security_headers if header not in headers]

        if missing_headers == 0:
            score = f"\n" + " " * 34 + f"Overall Score = {'A'}"
            print(score)
            html_score = f"<p class='a-score'>Overall Score = A</p>"
            section_html += html_score
        else:
            missing_headers_count = len(missing_headers)
            if missing_headers_count <= 2:
                score = f"\n" + " " * 34 + f"Overall Score = {'B'}"
                print(score)
                html_score = f"<p class='b-score'>Overall Score = B</p>"
                section_html += html_score
            elif missing_headers_count == 3:
                score = f"\n" + " " * 34 + f"Overall Score = {'C'}"
                print(score)
                html_score = f"<p class='c-score'>Overall Score = C</p>"
                section_html += html_score
            elif missing_headers_count == 4:
                score = f"\n" + " " * 34 + f"Overall Score = {'D'}"
                print(score)
                html_score = f"<p class='d-score'>Overall Score = D</p>"
                section_html += html_score
            elif missing_headers_count >= 5:
                score = f"\n" + " " * 34 + f"Overall Score = {'F'}"
                print(score)
                html_score = f"<p class='f-score'>Overall Score = F</p>"       
                section_html += html_score
        if missing_headers:
            for header in missing_headers:
                if  header != "Strict-Transport-Security":
                    hsts = 1
                if  header == "Strict-Transport-Security":
                    grade_counter = grade_counter + 1
                    print(
                        f'\n{header}: HTTP Strict Transport Security is an excellent feature to\nsupport on your site and strengthens your implementation of TLS by getting the User\nAgent to enforce the use of HTTPS. Recommended value "Strict-Transport-Security:\nmax-age=31536000; includeSubDomains".'
                    )
                    section_html += (
                        f'<p class="missing-header" ><b>{header}</b>: HTTP Strict Transport Security is an excellent feature to '
                        'support on your site and strengthens your implementation of TLS by getting the User '
                        'Agent to enforce the use of HTTPS. Recommended value "Strict-Transport-Security: '
                        'max-age=31536000; includeSubDomains".</p><br>'
                    )
                if  header == "Content-Security-Policy":
                    grade_counter = grade_counter + 1
                    print(
                        f"\n{header}: Content Security Policy is an effective measure to protect \nyour site from XSS attacks. By whitelisting sources of approved content, you can \nprevent the browser from loading malicious assets."
                    )
                    section_html += (
                        f'<p class="missing-header"><b>{header}</b>: Content Security Policy is an effective measure to protect '
                        'your site from XSS attacks. By whitelisting sources of approved content, you can '
                        'prevent the browser from loading malicious assets.</p><br>'
                    )
                if  header == "X-Frame-Options":
                    grade_counter = grade_counter + 1
                    print(
                        f'\n{header}: X-Frame-Options tells the browser whether you want to allow your site\nto be framed or not. By preventing a browser from framing your site you can defend\nagainst attacks like clickjacking. Recommended value "X-Frame-Options: SAMEORIGIN".'
                    )
                    section_html += (
                        f'<p class="missing-header"><b>{header}</b>: X-Frame-Options tells the browser whether you want to allow your site '
                        'to be framed or not. By preventing a browser from framing your site you can defend '
                        'against attacks like clickjacking. Recommended value "X-Frame-Options: SAMEORIGIN".</p><br>'
                    )
                if  header == "X-Content-Type-Options":
                    grade_counter = grade_counter + 1
                    print(
                        f'\n{header}: X-Content-Type-Options stops a browser from trying to\nMIME-sniff the content type and forces it to stick with the declared content-type. The\nonly valid value for this header is "X-Content-Type-Options: nosniff".'
                    )
                    section_html += (
                        f'<p class="missing-header"><b>{header}</b>: X-Content-Type-Options stops a browser from trying to '
                        'MIME-sniff the content type and forces it to stick with the declared content-type. The '
                        'only valid value for this header is "X-Content-Type-Options: nosniff".</p><br>'
                    )
                if  header == "Referrer-Policy":
                    grade_counter = grade_counter + 1
                    print(
                        f"\n{header}: Referrer Policy is a new header that allows a site to control how\nmuch information the browser includes with navigations away from a document and\nshould be set by all sites."
                    )
                    section_html += (
                        f'<p class="missing-header"><b>{header}</b>: Referrer Policy is a new header that allows a site to control how '
                        'much information the browser includes with navigations away from a document and '
                        'should be set by all sites.</p><br>'
                    )
                if  header == "Permissions-Policy":
                    grade_counter = grade_counter + 1
                    print(
                        f"\n{header}: Permissions Policy is a new header that allows a site to control\nwhich features and APIs can be used in the browser."
                    )
                    section_html += (
                        f'<p class="missing-header"><b>{header}</b>: Permissions Policy is a new header that allows a site to control how '
                        'which features and APIs can be used in the browser.</p><br>'
                    )
                if  header == 'X-XSS-Protection':
                    grade_counter = grade_counter + 1
                    print(f"\n{header}: X-XSS-Protection sets the configuration for the XSS Auditor\n built into older browsers. The recommended value was 'X-XSS-Protection: 1; mode=block'\n but you should now look at Content Security Policy instead.")
                    section_html += (
                        f'<p class="missing-header"><b>{header}</b>: X-XSS-Protection sets the configuration for the XSS Auditor '
                        'built into older browsers. The recommended value was "X-XSS-Protection: 1; mode=block" '
                        'but you should now look at Content Security Policy instead.</p><br>'
                    )
            section_html+= ("<p><a href='https://owasp.org/www-project-secure-headers/' class='small-text'>OWASP - Secure Headers Project</a></p>")
            html_report.append(section_html + "</div>")
        else:
            print("\nNo missing headers found.")
            section_html += ("<p class='secure'>No missing headers found.</p>")
            html_report.append(section_html + "</div>")
    except KeyboardInterrupt:
        print('\nYou either fat fingered this or something else. Either way, goodbye!\n')
        quit()
    except requests.exceptions.ConnectionError:
        print('\n[-] An issue occurred with connecting to the server. Check the URL and try again. Quitting...\n')
        quit()


def self_signed_check(target):
    print("\n" + "-" * 29 + "Self-Signed Certificate Check" + "-" * 28)
    html_report.append(
        """
    <div class="section">
        <div class="section-title">Self-Signed Certificate Check</div>
    """
    )
    try:
        response = requests.get(target)
        if 'http://' in target:
            print('\nHTTP in use. No certificate issued.')
            html_report.append("<p class='vulnerable'><b>HTTP protocol in use</b>. No certificate issued.</p>")
        else:
            print('\nCertificate has a valid certificate signature.')
            html_report.append("<p class='secure'>Certificate has a valid certificate signature.</p>")
    except requests.exceptions.SSLError:
        print("\nA self-signed certificate is in use")
        html_report.append("<p class='vulnerable'>A self-signed certificate is in use.</p>")
        html_report.append("<p><a href='https://owasp.org/www-project-secure-headers/' class='small-text'>OWASP - Secure Headers Project</a></p>")
    html_report.append("</div>")

def hsts_check(target):
    
    html_report.append(
        """
    <div class="section">
        <div class="section-title">Strict-Transport-Security Lifetime Check</div>
    """
    )
    try:
        print("\n" + "-" * 23 + "Strict-Transport-Security Lifetime Check" + "-" * 23)
        # with warnings.catch_warnings():
        #     warnings.simplefilter("ignore", category=urllib3.exceptions.InsecureRequestWarning)
        response = requests.get(target, verify=False)
        if response.status_code == 200:
            headers = response.headers
            for header, value in headers.items():
                if header.lower() == 'strict-transport-security':
                    directives = value.split(';')
                    max_age = directives[0]
                    max_age = max_age.split('=')[1].strip()
                    max_age1 = int(max_age)
                    if max_age1 < 31536000 and len(directives) <= 1:
                        print(f'\nMax Age: {max_age} - VULNERABLE - Max age too short; Missing includeSubdomains Directive.')
                        html_report.append(
                            f"<p class='vulnerable'><b>Max Age: {max_age} - VULNERABLE</b> - Max age too short; Missing includeSubdomains Directive.</p><p><a href='https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html' class='small-text'>OWASP HTTP Strict Transport Security - Cheat Sheet</a></p>"
                        )
                    elif max_age1 >= 31536000 and len(directives) <= 1:
                        print(f'\nMax Age: {max_age} - VULNERABLE - Missing includeSubDomains Directive.')
                        html_report.append(
                            f"<p class='vulnerable'><b>Max Age: {max_age} - VULNERABLE</b> - Missing includeSubdomains Directive.</p>"
                            f"<p><a href='https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html' class='small-text'>OWASP HTTP Strict Transport Security - Cheat Sheet</a></p>"
                        )
                    else:
                        print(f"\nMax Age: {max_age}; includeSubDomains - SECURE")
                        html_report.append(
                            f"<p class='secure'>Max Age: {max_age}; includeSubDomains - SECURE</p>"
                        )
            if 'strict-transport-security'.lower() not in headers:
                print(f'\nVULNERABLE - Missing HSTS header.')
                html_report.append(
                    f"<p class='vulnerable'><b>VULNERABLE</b> - Missing HSTS Header.</p><p><a href='https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html' class='small-text'>OWASP HTTP Strict Transport Security - Cheat Sheet</a></p>"
                    )
                pass
        else:
            print(f"Failed to retrieve {target}. Status code: {response.status_code}")
            html_report.append(
                f"<p>Failed to retrieve {target}. Status code: {response.status_code}</p>"
            )
    except Exception as e:
        print(e)
        print("\nAn error occurred when contacting the server.\n")
        html_report.append(
            "<p>An error occurred when contacting the server.</p>"
        )
    html_report.append("</div>")

def server_header_check(target):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=urllib3.exceptions.InsecureRequestWarning)
        found_header = 0
        possible_headers = ['Server', 'X-Powered-By']
        html_report.append(
            """
        <div class="section">
            <div class="section-title">Server Header Disclosure Check</div>
        """
        )
        try:
            print("\n" + "-" * 28 + "Server Header Disclosure Check" + "-" * 28 + "\n")
            response = requests.get(target, verify=False)
            for possible_header in possible_headers:
                server_header = response.headers.get(possible_header)
                if server_header == None:
                    pass
                if server_header == 'CLOUDFLARE'.lower():
                    pass
                elif server_header != None:
                    print(f"Server Header Disclosed: {server_header}")
                    found_header += 1
                    html_report.append(f"<p class='vulnerable'><b>Server Header Disclosed</b>: {server_header}</p>")

        except requests.RequestException as e:
            print(f"Request failed: {e}")
            html_report.append(f"<p>Request failed: {e}</p>")
        if found_header >= 1:
            html_report.append("<p><a href='https://owasp.org/www-project-secure-headers/' class='small-text'>OWASP - Secure Headers Project</a></p>")
        else:
            print("Server header not found.")
            html_report.append("<p class='secure'>Server header not found.</p>")
        html_report.append("</div>")
# def check_tls_version(hostname, port, tls_version):
#     try:
#         context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
#         context.check_hostname = False
#         context.verify_mode = ssl.CERT_NONE
#         if tls_version == 'TLSv1':
#             context.options |= ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3
#         elif tls_version == 'TLSv1.1':
#             context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3
#         elif tls_version == 'TLSv1.2':
#             context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_3
#         elif tls_version == 'TLSv1.3':
#             context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
#         else:
#             return False

#         # Connect to the server
#         with socket.create_connection((hostname, port)) as sock:
#             with context.wrap_socket(sock, server_hostname=hostname) as ssock:
#                 return ssock.version() == tls_version
#     except ssl.SSLError:
#         return False
#     except Exception as e:
#         print(f"Error connecting to {hostname}:{port} with {tls_version}: {e}")
#         return False

# def get_supported_tls_versions(hostname, port):
#     tls_versions = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']


#     for version in tls_versions:
#         if check_tls_version(hostname, port, version):
#             supported_versions.append(version)
        
#     return supported_versions
# def is_using_tls(url):
#     print("\n" + "-" * 39 + "TLS Check" + "-" * 38)
#     html_report.append(
#         """
#     <div class="section">
#         <div class="section-title">Transport Layer Security Check</div>
#     """
#     )
#     if not url.startswith(('http://', 'https://')):
#         url_no_http = url
#         url = 'http://' + url
#     parsed_url = urlparse(url)
#     if parsed_url.port:
#         return parsed_url.port
#     elif ':' in parsed_url.netloc:
#         _, port = parsed_url.netloc.split(':')
#         return int(port)
#     else:
#         port = 443    
#     try:
#         response = requests.get(url)
#         print('\nApplication utilizes the following TLS protocols:')
#         html_report.append(f"<p><b>Application utilizes the following TLS protocols:</b></p>")
#         get_supported_tls_versions(url_no_http, port)
#         for tls_version in supported_versions:
#             if tls_version == 'TLSv1.0':
#                 print(f'{tls_version} - VULNERABLE')
#                 html_report.append(f"<p class='vulnerable'><b>{tls_version}</b></p>"
#                 f"<p><a href='https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html' class='small-text'>OWASP - TLS Cheat Sheet</a></p>"
#                 )
#             if tls_version == 'TLSv1.1':
#                 print(f'{tls_version} - VULNERABLE')
#                 html_report.append(f"<p class='vulnerable'><b>{tls_version}</b></p>"
#                 f"<p><a href='https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html' class='small-text'>OWASP - TLS Cheat Sheet</a></p>"
#                 )
#             else:
#                 print(f'{tls_version}')
#                 html_report.append(f"<p class='secure'><b>{tls_version}</b></p>")    
#         html_report.append("</div>")
#         return response.url.startswith('https://')
#     except SSLError as e:
#         print('test 2')
#         print('\nApplication utilizes the following TLS protocols:')
#         html_report.append(f"<p><b>Application utilizes the following TLS protocols:</b></p>")
#         get_supported_tls_versions(url_no_http, port)
#         for tls_version in supported_versions:
#             if tls_version == 'TLSv1.0':
#                 print(f'{tls_version} - VULNERABLE')
#                 html_report.append(f"<p class='vulnerable'><b>{tls_version}</b></p>"
#                 f"<p><a href='https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html' class='small-text'>OWASP - TLS Cheat Sheet</a></p>"
#                 )
#             if tls_version == 'TLSv1.1':
#                 print(f'{tls_version} - VULNERABLE')
#                 html_report.append(f"<p class='vulnerable'><b>{tls_version}</b></p>"
#                 f"<p><a href='https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html' class='small-text'>OWASP - TLS Cheat Sheet</a></p>"
#                 )
#             else:
#                 print(f'{tls_version}')
#                 html_report.append(f"<p class='secure'><b>{tls_version}</b></p>")    
#         html_report.append("</div>")
#         return True
#     except requests.RequestException as e:
#         print('\nApplication does not utilize TLS - Vulnerable')
#         html_report.append(f"<p class='vulnerable'><b>Application does not use TLS protocols.</b></p></div>")
#         return False
def strip_http_https(url):
    if url.startswith("http://"):
        return url.replace("http://", "")
    elif url.startswith("https://"):
        return url.replace("https://", "")
    else:
        return url
def remove_after_first_slash(target_original):
    parsed_url = urlparse(target_original)
    path = parsed_url.path
    first_slash_index = path.find('/')
    if first_slash_index != -1:
        new_path = path[:first_slash_index]
    else:
        new_path = path
    new_url = urlunparse((parsed_url.scheme, parsed_url.netloc, new_path, '', '', ''))
    return new_url
def main():
    try:
        banner()
        target = input("\nWhat URL are we checking?: ").strip()
        target_original = strip_http_https(target)
        cleaned_url = remove_after_first_slash(target_original)
        if target == target_original:
            print('\n[!]Please re-run the tool using HTTP or HTTPS')
            quit()
        secondary_banner(target)        
        security_header_check(target)
        self_signed_check(target)
        hsts_check(target)
        server_header_check(target)
        
        html_report.append("</body></html>")
        with open(f"{cleaned_url}_low_hanging_fruit_report.html", "w") as file:
            file.write(''.join(html_report))
        print('\nScan complete.')
    except KeyboardInterrupt:
        print('\n\n[-] You either fat fingered this or something else. Either way, goodbye!\n')
        quit()
if __name__ == "__main__":
    main()

